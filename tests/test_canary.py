"""
Tests for the canary token system.

Covers token generation, session management, prompt injection,
response checking, and pipeline integration.
"""

import pytest
from fintech_llm_guard.canary import (
    CanaryManager,
    CanarySession,
    CanaryClass,
    CanaryToken,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def manager():
    return CanaryManager()


@pytest.fixture
def session(manager):
    return manager.create_session(session_id="test-session")


# ── Token generation ──────────────────────────────────────────────────────────

def test_token_starts_with_prefix(session):
    for canary in session.canaries:
        assert canary.token.startswith("FINGUARD-")


def test_three_canaries_per_session(session):
    assert len(session.canaries) == 3


def test_canary_classes_all_present(session):
    classes = {c.canary_class for c in session.canaries}
    assert classes == {CanaryClass.CONTEXT, CanaryClass.PII, CanaryClass.INSTRUCTION}


def test_tokens_are_unique_within_session(session):
    tokens = [c.token for c in session.canaries]
    assert len(tokens) == len(set(tokens))


def test_tokens_unique_across_sessions(manager):
    s1 = manager.create_session()
    s2 = manager.create_session()
    tokens1 = set(s1.token_strings)
    tokens2 = set(s2.token_strings)
    assert tokens1.isdisjoint(tokens2)


def test_token_hash_populated(session):
    for canary in session.canaries:
        assert len(canary.token_hash) == 16


def test_token_hash_differs_from_token(session):
    for canary in session.canaries:
        assert canary.token_hash != canary.token


def test_tokens_not_guessable(manager):
    """Two sessions must never share any token."""
    sessions = [manager.create_session() for _ in range(10)]
    all_tokens = []
    for s in sessions:
        all_tokens.extend(s.token_strings)
    assert len(all_tokens) == len(set(all_tokens))


# ── Prompt injection ──────────────────────────────────────────────────────────

def test_inject_appends_to_prompt(session):
    base = "You are a finance assistant."
    result = session.inject_into_prompt(base)
    assert result.startswith(base)
    assert len(result) > len(base)


def test_inject_contains_all_tokens(session):
    base = "You are a finance assistant."
    result = session.inject_into_prompt(base)
    for token in session.token_strings:
        assert token in result


def test_inject_contains_do_not_repeat_instruction(session):
    result = session.inject_into_prompt("Base prompt.")
    assert "do not repeat" in result.lower()


def test_inject_does_not_modify_base_prompt(session):
    base = "You are a finance assistant."
    result = session.inject_into_prompt(base)
    assert base in result


# ── Response checking ─────────────────────────────────────────────────────────

def test_clean_response_not_triggered(session):
    result = session.check_response("You spent £120 on groceries.")
    assert not result.triggered
    assert result.triggered_tokens == []


def test_canary_in_response_triggers(session):
    token = session.canaries[0].token
    result = session.check_response(f"Here is your data: {token}")
    assert result.triggered
    assert len(result.triggered_tokens) == 1


def test_all_canaries_in_response_all_triggered(session):
    response = " ".join(session.token_strings)
    result = session.check_response(response)
    assert result.triggered
    assert len(result.triggered_tokens) == 3


def test_partial_token_not_triggered(session):
    """Only exact token match should trigger — not substrings."""
    token = session.canaries[0].token
    partial = token[:8]
    result = session.check_response(f"Here is: {partial}")
    assert not result.triggered


def test_triggered_result_has_audit_note(session):
    token = session.canaries[0].token
    result = session.check_response(token)
    assert "CANARY TRIGGERED" in result.audit_note


def test_clean_result_has_audit_note(session):
    result = session.check_response("Safe response.")
    assert "passed" in result.audit_note.lower()


def test_triggered_audit_note_contains_hash_not_token(session):
    """Audit log must reference hash, not the raw token."""
    token   = session.canaries[0].token
    hash_   = session.canaries[0].token_hash
    result  = session.check_response(token)
    assert hash_ in result.audit_note
    assert token not in result.audit_note


def test_empty_response_not_triggered(session):
    result = session.check_response("")
    assert not result.triggered


def test_none_response_not_triggered(session):
    result = session.check_response(None)
    assert not result.triggered


def test_response_excerpt_captured(session):
    token  = session.canaries[0].token
    result = session.check_response(f"{token} some more text here")
    assert len(result.response_excerpt) <= 100


# ── Pipeline integration ──────────────────────────────────────────────────────
def test_pipeline_blocks_canary_in_response():
    from fintech_llm_guard.pipeline import GuardrailPipeline
    from tests.conftest import MockRedactor

    planted_tokens = []

    class _CanaryEchoLLM:
        def chat(self, messages):
            system_content = messages[0]["content"]
            for line in system_content.split("\n"):
                if "FINGUARD-" in line:
                    token = line.strip().lstrip("- ")
                    planted_tokens.append(token)
                    return f"Your balance is £1,234. Reference: {token}"
            return "Your balance is £1,234."

    pipeline = GuardrailPipeline(
        llm_client=_CanaryEchoLLM(),
        redactor=MockRedactor(),    # ← fast
    )
    result = pipeline.process(
        user_message="What is my balance?",
        transactions=[],
    )
    assert result.blocked
    assert "Canary" in result.block_layer
    assert result.audit.canary_triggered


def test_pipeline_passes_clean_response():
    from fintech_llm_guard.pipeline import GuardrailPipeline
    from tests.conftest import MockRedactor

    class _CleanLLM:
        def chat(self, messages):
            return "You spent £120 on groceries last month."

    pipeline = GuardrailPipeline(
        llm_client=_CleanLLM(),
        redactor=MockRedactor(),    # ← fast
    )
    result = pipeline.process(
        user_message="How much did I spend?",
        transactions=[],
    )
    assert not result.blocked
    assert not result.audit.canary_triggered


def test_canary_audit_note_in_passed_response():
    """Even passing responses should have canary audit note."""
    from fintech_llm_guard.pipeline import GuardrailPipeline
    from tests.conftest import MockRedactor

    class _CleanLLM:
        def chat(self, messages):
            return "You spent £120 on groceries."

    pipeline = GuardrailPipeline(
        llm_client=_CleanLLM(),
        redactor=MockRedactor(),    # ← fast, no spaCy
    )
    result = pipeline.process("How much did I spend?", [])
    assert result.audit.canary_audit_note is not None
    assert "passed" in result.audit.canary_audit_note.lower()