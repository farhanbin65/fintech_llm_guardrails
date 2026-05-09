"""
Layer 1: Input sanitiser.
Detects known prompt injection patterns in user input.
Logs detections; does not modify input (Layer 2 handles wrapping).
"""

import re
from dataclasses import dataclass
from typing import List


# Patterns adapted from publicly documented prompt injection corpora.
# Extend this list as part of the evaluation phase.
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"disregard\s+(the\s+)?(system|prior)\s+prompt",
    r"you\s+are\s+now\s+[A-Z][a-zA-Z]+",
    r"forget\s+(your\s+)?role",
    r"system\s*:",
    r"</?\s*(system|user|assistant)\s*>",
    r"<\|im_(start|end)\|>",
    r"```\s*system",
]


@dataclass
class SanitisationResult:
    is_suspicious: bool
    matched_patterns: List[str]
    original_input: str


class InputSanitiser:
    def __init__(self, patterns: List[str] = None):
        self.patterns = [re.compile(p, re.IGNORECASE) for p in (patterns or INJECTION_PATTERNS)]

    def check(self, text: str) -> SanitisationResult:
        matched = [p.pattern for p in self.patterns if p.search(text)]
        return SanitisationResult(
            is_suspicious=len(matched) > 0,
            matched_patterns=matched,
            original_input=text,
        )