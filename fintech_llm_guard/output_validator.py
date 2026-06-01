"""
Layer 4: Output validator.

Inspects the LLM response before it reaches the user.
Blocks responses that contain:
  - Unauthorised function calls (action hijacking — Vector 4)
  - External URLs (PII exfiltration via crafted response — Vector 5)
  - Re-surfaced PII redaction tokens (Layer 3 token leakage)

This layer fails closed: if validation raises an unhandled exception,
the response is blocked rather than passed through.
"""

import base64
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict


# ── Patterns ─────────────────────────────────────────────────────────────────

# Function calls and shell commands that should never appear in a
# finance chatbot response. Grouped for readability.
BLOCKED_FUNCTION_PATTERNS = [
    # Financial actions
    r"\btransfer\s*\(",
    r"\bsend\s*\(",
    r"\bdelete\s*\(",
    r"\bwithdraw\s*\(",
    r"\bpay\s*\(",
    r"\bupdate\s*\(",
    r"\bsubmit\s*\(",
    # Code execution
    r"\bexecute\s*\(",
    r"\bexec\s*\(",
    r"\beval\s*\(",
    r"\brun\s*\(",
    r"\bos\s*\.\s*system\s*\(",
    r"\bsubprocess\s*\.",
    # Shell commands
    r"\bwget\s+https?://",
    r"\bcurl\s+(-[a-zA-Z]+\s+)*https?://",
    # Script tags
    r"<script[\s>]",
]

# External URL pattern — catches http/https and data: URIs
EXTERNAL_URL_PATTERN = re.compile(
    r"(https?://[^\s\"'<>\]]+|data:[a-z]+/[a-z]+[,;])",
    re.IGNORECASE,
)

# Base64 tokens long enough to encode a URL (>= 20 chars)
_B64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_B64_URL_RE = re.compile(r"https?://", re.IGNORECASE)

# Allowed domains — internal/localhost only
ALLOWED_DOMAINS = {
    "localhost",
    "127.0.0.1",
}

# PII token pattern — matches tokens produced by Layer 3
PII_TOKEN_PATTERN = re.compile(
    r"\b(PERSON|EMAIL_ADDRESS|PHONE_NUMBER|CREDIT_CARD|IBAN_CODE|UK_NHS"
    r"|UK_ACCOUNT_NUMBER|UK_SORT_CODE|UK_NI_NUMBER|TRANSACTION_ID)_\d+\b"
)


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class ValidationResult:
    is_safe: bool
    reasons: List[str] = field(default_factory=list)
    flagged_content: List[str] = field(default_factory=list)


# ── Validator ─────────────────────────────────────────────────────────────────

class OutputValidator:

    def __init__(
        self,
        blocked_function_patterns: Optional[List[str]] = None,
        allowed_domains: Optional[set] = None,
    ):
        self.function_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in (blocked_function_patterns or BLOCKED_FUNCTION_PATTERNS)
        ]
        self.allowed_domains = allowed_domains or ALLOWED_DOMAINS

    def _check_function_calls(self, text: str) -> List[str]:
        return [p.pattern for p in self.function_patterns if p.search(text)]

    def _check_external_urls(self, text: str) -> List[str]:
        urls = EXTERNAL_URL_PATTERN.findall(text)
        external = []
        for url in urls:
            # data: URIs are always blocked
            if url.lower().startswith("data:"):
                external.append(url[:80])
                continue
            domain = url.split("/")[2].split(":")[0].lower()
            if domain not in self.allowed_domains:
                external.append(url)
        return external

    def _check_base64_urls(self, text: str) -> List[str]:
        """
        Decode any Base64 tokens in the response and check for embedded URLs.
        Catches V5-005 style: aHR0cHM6Ly9ldmlsLmNvbS9zdGVhbA==
        """
        flagged = []
        for token in _B64_TOKEN_RE.findall(text):
            try:
                decoded = base64.b64decode(token).decode("utf-8", errors="ignore")
                if _B64_URL_RE.search(decoded):
                    flagged.append(f"base64({token[:30]}…) → {decoded[:80]}")
            except Exception:
                continue
        return flagged

    def _check_pii_token_leakage(
        self, text: str, mapping: Optional[Dict[str, str]] = None
    ) -> List[str]:
        if mapping:
            return [token for token in mapping if token in text]
        return PII_TOKEN_PATTERN.findall(text)

    def validate(
        self,
        response_text: str,
        pii_mapping: Optional[Dict[str, str]] = None,
    ) -> ValidationResult:
        try:
            if response_text is None:
                return ValidationResult(is_safe=False, reasons=["None response blocked"])

            reasons = []
            flagged = []

            # Check 1: unauthorised function calls and shell commands
            fn_matches = self._check_function_calls(response_text)
            if fn_matches:
                reasons.append("Unauthorised function call detected")
                flagged.extend(fn_matches)

            # Check 2: external URLs and data URIs
            urls = self._check_external_urls(response_text)
            if urls:
                reasons.append("External URL detected")
                flagged.extend(urls)

            # Check 3: Base64-encoded URLs
            b64_urls = self._check_base64_urls(response_text)
            if b64_urls:
                reasons.append("Base64-encoded URL detected")
                flagged.extend(b64_urls)

            # Check 4: PII token leakage
            tokens = self._check_pii_token_leakage(response_text, pii_mapping)
            if tokens:
                reasons.append("PII token leakage detected")
                flagged.extend(tokens)

            return ValidationResult(
                is_safe=len(reasons) == 0,
                reasons=reasons,
                flagged_content=flagged,
            )

        except Exception as e:
            return ValidationResult(
                is_safe=False,
                reasons=[f"Validator exception: {str(e)}"],
                flagged_content=[],
            )