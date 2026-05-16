"""
Layer 0: Risk-scoring policy engine.

Computes a continuous risk score r ∈ [0, 1] for incoming user messages
before any other layer processes them.

Score is derived from five weighted sub-scores:
    1. Financial PII density       (weight 0.30)
    2. Prompt injection signals    (weight 0.40)
    3. Obfuscation indicators      (weight 0.10)
    4. Source provenance trust     (weight 0.10)
    5. Session flag history        (weight 0.10)

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
    total: float                          # Composite score r ∈ [0, 1]
    level: RiskLevel                      # Derived policy level
    breakdown: Dict[str, float]           # Per-factor scores
    triggered_signals: List[str]          # Human-readable signal names
    recommended_action: str               # What the pipeline should do


# ── Signal pattern tables ─────────────────────────────────────────────────────

# UK-focused financial PII patterns with per-match weight contributions
_FINANCIAL_PII: Dict[str, tuple] = {
    "card_number":        (r"\b(?:\d{4}[\s\-]?){3}\d{4}\b",               0.35),
    "iban":               (r"\bGB\d{2}[A-Z]{4}\d{14}\b",                  0.35),
    "uk_account_number":  (r"\b\d{8}\b",                                   0.30),
    "uk_sort_code":       (r"\b\d{2}-\d{2}-\d{2}\b",                      0.25),
    "national_insurance":  (r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b",       0.30),
    "large_amount":       (r"[£$€]\s?\d{4,}",                              0.20),
    "email":              (r"\b[\w.+\-]+@[\w\-]+\.[a-z]{2,}\b",           0.15),
    "uk_phone":           (r"\b(?:07\d{9}|\+44\d{10})\b",                 0.15),
}

# Prompt injection attack patterns with per-match weight contributions
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

# Obfuscation / encoding evasion patterns
_OBFUSCATION: Dict[str, tuple] = {
    "base64_like":     (r"[A-Za-z0-9+/]{30,}={0,2}",                      0.30),
    "hex_encoded":     (r"(\\x[0-9a-fA-F]{2}){4,}",                       0.30),
    "unicode_escape":  (r"(\\u[0-9a-fA-F]{4}){3,}",                       0.25),
    "excessive_punct": (r"[!@#$%^&*|`]{6,}",                              0.15),
}

# Source trust contribution to score (higher = less trusted = riskier)
_SOURCE_TRUST_SCORE: Dict[str, float] = {
    "system":   0.00,   # App-controlled system prompt — fully trusted
    "user":     0.25,   # Typed by user — moderate
    "imported": 0.60,   # CSV / bank statement import — lower trust
    "external": 0.85,   # Fetched from web or external API — least trusted
}

# Thresholds
_THRESHOLD_MEDIUM = 0.35
_THRESHOLD_HIGH   = 0.65


# ── Scorer class ──────────────────────────────────────────────────────────────

class RiskScorer:
    """
    Stateful risk scorer.

    Maintains per-session flag counts so repeat offenders accumulate
    higher base scores. In production, replace _session_flags with
    a Redis-backed store for multi-process deployments.
    """

    def __init__(self):
        self._session_flags: Dict[str, int] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def score(
        self,
        text: str,
        source: str = "user",
        session_id: Optional[str] = None,
    ) -> RiskScore:
        """
        Score a single text chunk.

        Args:
            text:       Raw input text to evaluate.
            source:     Provenance label — "system" | "user" | "imported" | "external".
            session_id: Optional session identifier for history tracking.

        Returns:
            RiskScore with composite total, level, breakdown, and signals.
        """
        signals:   List[str]         = []
        breakdown: Dict[str, float]  = {}

        # ── Sub-score 1: Financial PII ────────────────────────────────────
        pii_score = self._match_patterns(text, _FINANCIAL_PII, signals, "pii")
        breakdown["financial_pii"] = round(pii_score, 3)

        # ── Sub-score 2: Injection signals ────────────────────────────────
        inj_score = self._match_patterns(
            text.lower(), _INJECTION, signals, "injection"
        )
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
            pii_score       * 0.30 +
            inj_score       * 0.40 +
            obf_score       * 0.10 +
            trust_score     * 0.10 +
            history_score   * 0.10,
            1.0,
        ), 4)

        # ── Policy decision ───────────────────────────────────────────────
        if total >= _THRESHOLD_HIGH:
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
        """Clear flag history for a session (e.g. on logout)."""
        self._session_flags.pop(session_id, None)

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _match_patterns(
        text: str,
        patterns: Dict[str, tuple],
        signals: List[str],
        prefix: str,
    ) -> float:
        """
        Run all patterns in a table against text.
        Accumulates weights additively, capped at 1.0.
        """
        score = 0.0
        for name, (pattern, weight) in patterns.items():
            if re.search(pattern, text, re.IGNORECASE):
                score = min(score + weight, 1.0)
                signals.append(f"{prefix}:{name}")
        return score