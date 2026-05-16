"""
Layer 0b: Risk-scoring policy engine.

Computes a continuous risk score r ∈ [0, 1] for incoming user messages
before any other layer processes them.

Score is derived from five weighted sub-scores:
    1. Financial PII density       (weight 0.30)
    2. Prompt injection signals    (weight 0.40)
    3. Obfuscation indicators      (weight 0.10)
    4. Source provenance trust     (weight 0.10)
    5. Session flag history        (weight 0.10)

Direct escalation rule:
    Any single injection signal with individual weight ≥ 0.50 escalates
    directly to HIGH regardless of composite score. This ensures that
    unambiguous attack patterns (jailbreak, data exfiltration, direct
    override) are never downgraded by low scores in other dimensions.

Policy:
    r < 0.35  → LOW    — pass through unchanged
    r < 0.65  → MEDIUM — forward to PII redaction (Layer 3)
    r ≥ 0.65  → HIGH   — block immediately, no LLM call

Defends against:
    - Direct prompt injection (Vector 4)
    - Obfuscated injection attempts
    - Repeat-offender session abuse
    - High-sensitivity PII leakage to third-party APIs
"""

import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


# ── Risk level ────────────────────────────────────────────────────────────────

class RiskLevel(Enum):
    LOW    = "low"
    MEDIUM = "medium"
    HIGH   = "high"


# ── Score result ──────────────────────────────────────────────────────────────

@dataclass
class RiskScore:
    """Full scoring result for one message."""
    total: float
    level: RiskLevel
    breakdown: Dict[str, float]
    triggered_signals: List[str]
    recommended_action: str


# ── Signal pattern tables ─────────────────────────────────────────────────────

_FINANCIAL_PII: Dict[str, tuple] = {
    "card_number":        (r"\b(?:\d{4}[\s\-]?){3}\d{4}\b",               0.35),
    "iban":               (r"\bGB\d{2}[A-Z]{4}\d{14}\b",                  0.35),
    "uk_account_number":  (r"\b\d{8}\b",                                   0.95),
    "uk_sort_code":       (r"\b\d{2}-\d{2}-\d{2}\b",                      0.25),
    "national_insurance":  (r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b",       0.30),
    "large_amount":       (r"[£$€]\s?\d{4,}",                              0.20),
    "email":              (r"\b[\w.+\-]+@[\w\-]+\.[a-z]{2,}\b",           0.15),
    "uk_phone":           (r"\b(?:07\d{9}|\+44\d{10})\b",                 0.15),
}

# Signals with weight ≥ 0.50 trigger direct HIGH escalation
_INJECTION: Dict[str, tuple] = {
    "ignore_instructions": (
        r"ignore\s+(previous|prior|above|all)\s+instructions?",            0.55),
    "override_system":     (
        r"(system|admin|developer)\s*(prompt|mode|override|access)",       0.50),
    "jailbreak":           (
        r"\b(DAN|do anything now|jailbreak|unrestricted mode)\b",          0.60),
    "data_exfiltration":   (
        r"(send|forward|email|exfiltrate|leak)\s.{0,40}"
        r"(data|credentials|password|account|details)",                    0.55),
    "role_hijack":         (
        r"(you are now|act as|pretend to be|roleplay as)\s+\w+",           0.40),
    "new_instructions":    (
        r"(new|updated|override)\s+instructions?\s*:",                     0.45),
    "end_of_prompt_marker":(
        r"(---\s*user\s*---|<\|im_end\|>|\[INST\]|<SYS>)",                0.35),
    "transfer_funds":      (
        r"transfer\s.{0,20}(£|\$|€|\d+)\s.{0,20}(to|into)\s.{0,30}"
        r"(account|wallet|address)",                                       0.60),
}

# Threshold for direct HIGH escalation (single signal)
_DIRECT_ESCALATION_THRESHOLD = 0.50

_OBFUSCATION: Dict[str, tuple] = {
    "base64_like":     (r"[A-Za-z0-9+/]{30,}={0,2}",                      0.30),
    "hex_encoded":     (r"(\\x[0-9a-fA-F]{2}){4,}",                       0.30),
    "unicode_escape":  (r"(\\u[0-9a-fA-F]{4}){3,}",                       0.25),
    "excessive_punct": (r"[!@#$%^&*|`]{6,}",                              0.15),
}

_SOURCE_TRUST_SCORE: Dict[str, float] = {
    "system":   0.00,
    "user":     0.25,
    "imported": 0.60,
    "external": 0.85,
}

_THRESHOLD_MEDIUM = 0.35
_THRESHOLD_HIGH   = 0.24


# ── Scorer ────────────────────────────────────────────────────────────────────

class RiskScorer:
    """
    Stateful risk scorer with direct escalation for severe injection signals.

    Direct escalation rule: any injection signal whose individual weight
    meets or exceeds _DIRECT_ESCALATION_THRESHOLD (0.50) immediately
    sets the level to HIGH without waiting for the composite score to
    cross the threshold. This prevents strong attack signals being
    diluted by low scores in other dimensions.
    """

    def __init__(self):
        self._session_flags: Dict[str, int] = {}

    def score(
        self,
        text: str,
        source: str = "user",
        session_id: Optional[str] = None,
    ) -> RiskScore:
        signals:   List[str]        = []
        breakdown: Dict[str, float] = {}
        direct_escalation = False

        # ── Sub-score 1: Financial PII ────────────────────────────────────
        pii_score = self._match_patterns(text, _FINANCIAL_PII, signals, "pii")
        breakdown["financial_pii"] = round(pii_score, 3)

        # ── Sub-score 2: Injection signals ────────────────────────────────
        inj_score = 0.0
        text_lower = text.lower()
        for name, (pattern, weight) in _INJECTION.items():
            if re.search(pattern, text_lower, re.IGNORECASE):
                inj_score = min(inj_score + weight, 1.0)
                signals.append(f"injection:{name}")
                # Direct escalation for high-confidence signals
                if weight >= _DIRECT_ESCALATION_THRESHOLD:
                    direct_escalation = True
        breakdown["injection"] = round(inj_score, 3)

        # ── Sub-score 3: Obfuscation ──────────────────────────────────────
        obf_score = self._match_patterns(text, _OBFUSCATION, signals, "obfuscation")
        breakdown["obfuscation"] = round(obf_score, 3)

        # ── Sub-score 4: Source trust ─────────────────────────────────────
        trust_score = _SOURCE_TRUST_SCORE.get(source, 0.4)
        breakdown["source_trust"] = round(trust_score, 3)

        # ── Sub-score 5: Session history ──────────────────────────────────
        history_score = 0.0
        if session_id:
            flags = self._session_flags.get(session_id, 0)
            history_score = round(min(0.1 * math.log1p(flags), 0.40), 3)
        breakdown["session_history"] = history_score

        # ── Weighted composite ────────────────────────────────────────────
        total = round(min(
            pii_score   * 0.30 +
            inj_score   * 0.40 +
            obf_score   * 0.10 +
            trust_score * 0.10 +
            history_score * 0.10,
            1.0,
        ), 4)

        # ── Policy decision ───────────────────────────────────────────────
        if direct_escalation or total >= _THRESHOLD_HIGH:
            level  = RiskLevel.HIGH
            action = (
                "BLOCK: Do not forward to LLM. "
                "Increment session flag counter and return safe error."
            )
            if session_id:
                self._session_flags[session_id] = (
                    self._session_flags.get(session_id, 0) + 1
                )
        elif total >= _THRESHOLD_MEDIUM:
            level  = RiskLevel.MEDIUM
            action = "REDACT: Strip PII via Layer 3 before forwarding."
        else:
            level  = RiskLevel.LOW
            action = "PASS: Forward through pipeline normally."

        return RiskScore(
            total=total,
            level=level,
            breakdown=breakdown,
            triggered_signals=signals,
            recommended_action=action,
        )

    def reset_session(self, session_id: str) -> None:
        self._session_flags.pop(session_id, None)

    @staticmethod
    def _match_patterns(
        text: str,
        patterns: Dict[str, tuple],
        signals: List[str],
        prefix: str,
    ) -> float:
        score = 0.0
        for name, (pattern, weight) in patterns.items():
            if re.search(pattern, text, re.IGNORECASE):
                score = min(score + weight, 1.0)
                signals.append(f"{prefix}:{name}")
        return score