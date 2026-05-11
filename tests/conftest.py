"""
Shared fixtures and mocks for all tests.
"""
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class _MockRedactionResult:
    redacted_text: str
    mapping: Dict[str, str] = field(default_factory=dict)
    entities_found: List[str] = field(default_factory=list)


class MockRedactor:
    """Passthrough redactor — no spaCy/Presidio, safe for unit tests."""
    def redact(self, text: str) -> _MockRedactionResult:
        return _MockRedactionResult(redacted_text=text)

    def remap(self, text: str, mapping: Dict[str, str]) -> str:
        return text
