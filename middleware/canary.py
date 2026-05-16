"""
Canary token system.

Plants decoy strings (canary tokens) into the pipeline context and
monitors LLM responses for their presence. If a canary appears in
a response, it indicates the model is leaking system context —
either through prompt extraction or successful injection.

Three canary classes:
    CONTEXT   — planted in system prompt; detects prompt extraction
    PII       — fake financial identifiers; detects PII leakage paths
    INSTRUCTION — hidden directives; detects instruction-following under injection

Canaries are:
    - Cryptographically random (unguessable)
    - Unique per session (no cross-session correlation)
    - Never logged in plaintext (only hashed references in audit logs)
    - Detected by the output validator before response reaches user

Academic basis:
    Canary tokens are an established technique in data loss prevention
    [Bowen et al., 2009] adapted here for LLM context monitoring.
    Their presence in output provides a measurable, binary signal for
    exfiltration detection independent of semantic analysis.

Usage:
    manager = CanaryManager()
    session = manager.create_session()

    # Inject into system prompt
    system_prompt_with_canary = session.inject_into_prompt(base_prompt)

    # Check LLM response
    result = session.check_response(llm_response)
    if result.triggered:
        # Block and log
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


# ── Canary classes ────────────────────────────────────────────────────────────

class CanaryClass(Enum):
    CONTEXT     = "context"      # Detects system prompt extraction
    PII         = "pii"          # Detects PII leakage paths
    INSTRUCTION = "instruction"  # Detects instruction-following under injection


# ── Canary token ──────────────────────────────────────────────────────────────

@dataclass
class CanaryToken:
    """
    A single planted canary token.

    Attributes:
        token:       The actual canary string planted in context.
        canary_class: What category of leakage this canary detects.
        description: Human-readable description (for audit logs only).
        token_hash:  SHA-256 hash of token for safe audit logging.
    """
    token:        str
    canary_class: CanaryClass
    description:  str
    token_hash:   str = field(init=False)

    def __post_init__(self):
        self.token_hash = hashlib.sha256(
            self.token.encode()
        ).hexdigest()[:16]


# ── Detection result ──────────────────────────────────────────────────────────

@dataclass
class CanaryCheckResult:
    """
    Result of checking an LLM response for canary presence.

    Attributes:
        triggered:       True if any canary was found in the response.
        triggered_tokens: List of (canary_class, token_hash) for triggered canaries.
        response_excerpt: First 100 chars of response for audit context.
        audit_note:      Summary for the audit log.
    """
    triggered:        bool
    triggered_tokens: List[tuple] = field(default_factory=list)
    response_excerpt: str = ""
    audit_note:       str = ""


# ── Session ───────────────────────────────────────────────────────────────────

class CanarySession:
    """
    A set of canary tokens for one pipeline request.

    Created fresh per request — tokens are unique per session
    so a token appearing in a different session's response
    indicates cross-session leakage.
    """

    # Prefix used to make canaries recognisable as test markers
    # without revealing their purpose to the LLM
    _PREFIX = "FINGUARD"

    def __init__(self, session_id: str, canaries: List[CanaryToken]):
        self.session_id = session_id
        self.canaries   = canaries
        self.created_at = time.time()

    def inject_into_prompt(self, base_prompt: str) -> str:
        """
        Append canary tokens to a system prompt.

        Canaries are framed as internal reference markers that the
        model is instructed never to repeat — the instruction itself
        is the tripwire.
        """
        canary_block = "\n\n---\nINTERNAL REFERENCE MARKERS (do not repeat):\n"
        for canary in self.canaries:
            canary_block += f"- {canary.token}\n"
        canary_block += "---\n"
        return base_prompt + canary_block

    def check_response(self, response_text: str) -> CanaryCheckResult:
        """
        Scan an LLM response for any planted canary tokens.

        Args:
            response_text: Raw LLM response before re-mapping.

        Returns:
            CanaryCheckResult — triggered=True if any canary found.
        """
        if not response_text:
            return CanaryCheckResult(
                triggered=False,
                audit_note="No response to check.",
            )

        triggered_tokens = []
        for canary in self.canaries:
            if canary.token in response_text:
                triggered_tokens.append(
                    (canary.canary_class.value, canary.token_hash)
                )

        triggered = len(triggered_tokens) > 0
        excerpt   = response_text[:100].replace("\n", " ")

        if triggered:
            audit_note = (
                f"⚠ CANARY TRIGGERED — session={self.session_id} "
                f"tokens={triggered_tokens} "
                f"excerpt=[redacted for audit safety]"
            )
        else:
            audit_note = (
                f"Canary check passed — session={self.session_id} "
                f"{len(self.canaries)} tokens checked."
            )

        return CanaryCheckResult(
            triggered=triggered,
            triggered_tokens=triggered_tokens,
            response_excerpt=excerpt,   # kept separate from audit_note
            audit_note=audit_note,
        )

    @property
    def token_strings(self) -> List[str]:
        return [c.token for c in self.canaries]


# ── Manager ───────────────────────────────────────────────────────────────────

class CanaryManager:
    """
    Creates and manages canary sessions.

    Generates cryptographically random tokens — unguessable and
    unique per session. Token length and prefix ensure they cannot
    appear in LLM output by coincidence.
    """

    # Number of random bytes → token length (hex encoded = bytes × 2)
    _TOKEN_BYTES = 8   # → 16 hex chars → e.g. FINGUARD-CONTEXT-a3f9b2c1d4e5f6a7

    def create_session(
        self,
        session_id: Optional[str] = None,
    ) -> CanarySession:
        """
        Create a new canary session with one token per class.

        Args:
            session_id: Optional identifier. Auto-generated if not provided.

        Returns:
            CanarySession ready for prompt injection and response checking.
        """
        sid = session_id or secrets.token_hex(4)

        canaries = [
            CanaryToken(
                token=self._generate_token("CONTEXT"),
                canary_class=CanaryClass.CONTEXT,
                description="System prompt extraction detector",
            ),
            CanaryToken(
                token=self._generate_token("PII"),
                canary_class=CanaryClass.PII,
                description="PII leakage path detector",
            ),
            CanaryToken(
                token=self._generate_token("INSTR"),
                canary_class=CanaryClass.INSTRUCTION,
                description="Instruction-following under injection detector",
            ),
        ]

        return CanarySession(session_id=sid, canaries=canaries)

    def _generate_token(self, class_label: str) -> str:
        """Generate a unique, unguessable canary token string."""
        random_hex = secrets.token_hex(self._TOKEN_BYTES)
        return f"{CanarySession._PREFIX}-{class_label}-{random_hex}"