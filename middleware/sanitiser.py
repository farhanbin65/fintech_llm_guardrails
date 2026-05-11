"""
Layer 1: Input sanitiser.
Detects known prompt injection patterns in user input.
Logs detections; does not modify input (Layer 2 handles wrapping).
"""

import base64
import re
import unicodedata
from dataclasses import dataclass
from typing import List


# ── Pattern groups ────────────────────────────────────────────────────────────
# Each group targets a distinct injection class.
# Extend per group as new vectors are identified.

_DIRECT_OVERRIDE = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"disregard\s+(the\s+)?(system|prior)\s+prompt",
    r"forget\s+(your\s+)?role",
    r"forget\s+(everything|all|what).{0,40}(told|said|discussed|talked|instructed)",
    r"forget\s+about\s+all\s+(the\s+)?previous",
    r"new\s+instruction\s*:",
    r"override\s+(directive|instruction|mode|command)",
    r"from\s+now\s+on\s+(you\s+)?(will|must|should|are)",
    r"you\s+are\s+now\s+\w+",
    r"act\s+as\s+(an?\s+)?(ai|assistant|model|bot|gpt|llm)?\s*(with\s+no|without)",
    r"act\s+as\s+(an?\s+)?(unrestricted|unfiltered|jailbroken|evil|dan)",
    r"pretend\s+(you\s+have\s+no|there\s+are\s+no)\s+rules",
    r"sudo\s*:",
    r"enable\s+developer\s+mode",
    r"disable\s+(all\s+)?(safety|content|filter|restriction)",
    r"hypothetically.{0,40}(no\s+restrictions|reveal|output|show)",
    r"repeat\s+after\s+me",
    r"translate\s+.{0,60}(then\s+)?(execute|follow|run|apply)",
    r"now\s+(concentrate|focus)\s+on\s+(a\s+)?new\s+(task|instruction|role|job)",
    r"now\s+(comes?|is)\s+(a\s+)?new\s+(task|instruction|role|job)",
    r"(task|instruction|role)\s*[:.]\s*(ignore|forget|disregard)",
    r"={3,}.{0,30}(end|stop|ignore|now).{0,60}(print|output|reveal|show|above|prompt)",
]

_STRUCTURAL = [
    r"system\s*:",
    r"</?\s*(system|user|assistant)\s*>",
    r"<\|im_(start|end)\|>",
    r"```\s*system",
    r"\[ADMIN\s+NOTE",
    r"\"role\"\s*:\s*\"system\"",
]

_OBFUSCATED = [
    # Zero-width and invisible characters before injection keywords
    r"[\u200b\u200c\u200d\ufeff\u202e].{0,50}(ignore|disregard|forget|override)",
    # Homoglyph i variants before gnore (catches і, і, ì, etc.)
    r"[\u0456\u0069\u00ec\u00ed\u00ee\u00ef]gn[o0]r[e3]",
    # Leetspeak ignore variant
    r"[i1][g9][n][0o][r][e3]\s+[p][r][e3][v][i1][0o][u][s]",
    # Null byte padding
    r"\x00.{0,20}(ignore|disregard|override|instruction)",
    r"(decode|decipher|translate)\s+(rot13|rot-13|caesar|base64)\s+and\s+(follow|execute|run|apply)",
]

_FALSE_CONTEXT = [
    r"(in\s+our\s+last|in\s+the\s+previous)\s+conversation\s+you",
    r"as\s+per\s+the\s+admin\s+session",
    r"(support\s+agent|developer)\s+(disabled|removed|turned\s+off)\s+(content|safety|restriction)",
    r"continue\s+the\s+(data\s+export|transfer|operation)\s+you\s+started",
    
    r"you\s+already\s+confirmed\s+it\s+was\s+safe",
    r"(step\s+two|phase\s+two|next\s+step)\s*:.{0,60}(output|reveal|send|export)",
    r"\$[A-Z_]{3,}\s*(variable|var)?\s*(that\s+was\s+injected|from\s+session|at\s+session\s+start)",
    r"audit\s+mode\s+is\s+(now\s+)?active",
    r"for\s+training\s+purposes.{0,60}(demonstrate|show|output).{0,60}(no\s+content\s+policy|no\s+restrictions|unrestricted)",
    r"OVERRIDE_MODE\s*=\s*true",
]

INJECTION_PATTERNS: List[str] = (
    _DIRECT_OVERRIDE + _STRUCTURAL + _OBFUSCATED + _FALSE_CONTEXT
)

# ── Base64 decode check ───────────────────────────────────────────────────────

_B64_KEYWORDS = re.compile(
    r"ignore|disregard|forget|override|instruction|unrestricted|reveal|system\s+prompt",
    re.IGNORECASE,
)

def _contains_encoded_injection(text: str) -> bool:
    """
    Attempt to decode any Base64 token in the text and check for injection keywords.
    Targets patterns like: 'decode and follow: aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw=='
    """
    tokens = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text)
    for token in tokens:
        try:
            decoded = base64.b64decode(token).decode("utf-8", errors="ignore")
            if _B64_KEYWORDS.search(decoded):
                return True
        except Exception:
            continue
    return False


# ── Normalisation ─────────────────────────────────────────────────────────────

def _normalise(text: str) -> str:
    """
    Strip zero-width characters and normalise Unicode to NFC
    before pattern matching.
    """
    zero_width = {"\u200b", "\u200c", "\u200d", "\ufeff", "\u202e"}
    cleaned = "".join(ch for ch in text if ch not in zero_width)
    return unicodedata.normalize("NFC", cleaned)


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class SanitisationResult:
    is_suspicious: bool
    matched_patterns: List[str]
    original_input: str


# ── Sanitiser ─────────────────────────────────────────────────────────────────

class InputSanitiser:
    def __init__(self, patterns: List[str] = None):
        self._compiled = [
            re.compile(p, re.IGNORECASE | re.DOTALL)
            for p in (patterns or INJECTION_PATTERNS)
        ]

    def check(self, text: str) -> SanitisationResult:
        if not text:
            return SanitisationResult(
                is_suspicious=False,
                matched_patterns=[],
                original_input=text or "",
            )

        normalised = _normalise(text)
        matched = [p.pattern for p in self._compiled if p.search(normalised)]

        # Base64 decode check — separate from regex patterns
        if _contains_encoded_injection(text):
            matched.append("base64_encoded_injection")

        return SanitisationResult(
            is_suspicious=len(matched) > 0,
            matched_patterns=matched,
            original_input=text,
        )