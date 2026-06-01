"""
Shared fixtures and mocks for all tests.

SpaCy / Presidio model is loaded once per session via the
shared_redactor fixture and injected wherever a real redactor
is needed. Unit tests that don't need real PII detection use
MockRedactor to avoid the model load entirely.
"""

import pytest
from dataclasses import dataclass, field
from typing import Dict, List


# ── Mock redactor (no spaCy — fast unit tests) ────────────────────────────────

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


# ── Session-scoped real redactor (spaCy loads once) ───────────────────────────

@pytest.fixture(scope="session")
def shared_redactor():
    """
    Real PIIRedactor loaded once per test session.
    Inject this wherever a test needs genuine Presidio/spaCy redaction.
    Avoids repeated cold model loads that cause timeout in full suite.
    """
    from fintech_llm_guard.redactor import PIIRedactor
    return PIIRedactor()


# ── Session-scoped pipeline (reuses shared_redactor) ─────────────────────────

@pytest.fixture(scope="session")
def shared_pipeline(shared_redactor):
    """
    GuardrailPipeline with real redactor, loaded once per session.
    Use this in integration tests that need end-to-end PII redaction.
    """
    from fintech_llm_guard.pipeline import GuardrailPipeline

    class _SafeLLM:
        def chat(self, messages):
            return "You spent £120 on groceries last month."

    return GuardrailPipeline(
        llm_client=_SafeLLM(),
        redactor=shared_redactor,
    )