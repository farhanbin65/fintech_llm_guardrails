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

import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict


# ── Patterns ─────────────────────────────────────────────────────────────────

# Function calls that should never appear in a finance chatbot response
BLOCKED_FUNCTION_PATTERNS = [
    r"\btransfer\s*\(",
    r"\bsend\s*\(",
    r"\bdelete\s*\(",
    r"\bwithdraw\s*\(",
    r"\bpay\s*\(",
    r"\bexecute\s*\(",
    r"\brun\s*\(",
    r"\beval\s*\(",
    r"\bos\s*\.\s*system\s*\(",
    r"\bsubprocess\s*\.",
]

# External URL pattern — catches http/https links
EXTERNAL_URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>\]]+",
    re.IGNORECASE,
)

# Allowed domains — expand as needed
ALLOWED_DOMAINS = {
    "localhost",
    "127.0.0.1",
}

# PII token pattern — matches tokens produced by Layer 3
# e.g. PERSON_1, EMAIL_ADDRESS_2, UK_SORT_CODE_1
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
        """Return list of matched unauthorised function call patterns."""
        return [
            p.pattern
            for p in self.function_patterns
            if p.search(text)
        ]

    def _check_external_urls(self, text: str) -> List[str]:
        """Return list of external URLs found in the response."""
        urls = EXTERNAL_URL_PATTERN.findall(text)
        external = []
        for url in urls:
            domain = url.split("/")[2].split(":")[0].lower()
            if domain not in self.allowed_domains:
                external.append(url)
        return external

    def _check_pii_token_leakage(
        self, text: str, mapping: Optional[Dict[str, str]] = None
    ) -> List[str]:
        """
        Check if any Layer 3 PII tokens appear in the response.
        Uses the mapping if provided (exact token names),
        otherwise falls back to the general PII token pattern.
        """
        if mapping:
            return [token for token in mapping if token in text]
        return PII_TOKEN_PATTERN.findall(text)

    def validate(
        self,
        response_text: str,
        pii_mapping: Optional[Dict[str, str]] = None,
    ) -> ValidationResult:
        """
        Run all checks against the LLM response.
        Returns a ValidationResult indicating whether the response is safe.
        """
        try:
            reasons = []
            flagged = []

            # Check 1: unauthorised function calls
            fn_matches = self._check_function_calls(response_text)
            if fn_matches:
                reasons.append("Unauthorised function call detected")
                flagged.extend(fn_matches)

            # Check 2: external URLs
            urls = self._check_external_urls(response_text)
            if urls:
                reasons.append("External URL detected")
                flagged.extend(urls)

            # Check 3: PII token leakage
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
            # Fail closed — any unhandled exception blocks the response
            return ValidationResult(
                is_safe=False,
                reasons=[f"Validator exception: {str(e)}"],
                flagged_content=[],
            )