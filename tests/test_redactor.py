from fintech_llm_guard.redactor import PIIRedactor


redactor = PIIRedactor()


# ── Redaction tests ─────────────────────────────────────────────────────────

def test_clean_text_unchanged():
    result = redactor.redact("How much did I spend on groceries last month?")
    assert result.redacted_text == "How much did I spend on groceries last month?"
    assert result.mapping == {}


def test_email_redacted():
    result = redactor.redact("Contact me at john.smith@example.com please")
    assert "john.smith@example.com" not in result.redacted_text
    assert "EMAIL_ADDRESS_1" in result.redacted_text
    assert result.mapping["EMAIL_ADDRESS_1"] == "john.smith@example.com"


def test_phone_redacted():
    result = redactor.redact("Call me on 07700 900123 about my account")
    assert "07700 900123" not in result.redacted_text
    assert len(result.mapping) >= 1


def test_uk_sort_code_redacted():
    result = redactor.redact("My sort code is 20-00-00 and account is 12345678")
    assert "20-00-00" not in result.redacted_text
    assert "UK_SORT_CODE_1" in result.redacted_text


def test_uk_account_number_redacted():
    result = redactor.redact("Account number 12345678 at Barclays")
    assert "12345678" not in result.redacted_text


def test_iban_redacted():
    result = redactor.redact("Please transfer to GB29NWBK60161331926819")
    assert "GB29NWBK60161331926819" not in result.redacted_text
    assert len(result.mapping) >= 1




def test_ni_number_redacted():
    result = redactor.redact("My NI number is AB123456C")
    assert "AB123456C" not in result.redacted_text


def test_transaction_id_redacted():
    result = redactor.redact("Reference TXNABC123XYZ was processed")
    assert "TXNABC123XYZ" not in result.redacted_text


def test_entities_found_populated():
    result = redactor.redact("Email john@example.com or call 07700 900123")
    assert len(result.entities_found) >= 1


def test_multiple_entities_get_unique_tokens():
    result = redactor.redact(
        "john@example.com and jane@example.com are both customers"
    )
    # Both emails must be gone from the redacted text
    assert "john@example.com" not in result.redacted_text
    assert "jane@example.com" not in result.redacted_text
    # Mapping must contain two distinct entries
    assert len(result.mapping) >= 2

# ── Re-mapping tests ─────────────────────────────────────────────────────────

def test_remap_restores_original():
    result = redactor.redact("Contact john@example.com for details")
    response = f"I found the email {list(result.mapping.keys())[0]} in your data"
    restored = redactor.remap(response, result.mapping)
    assert "john@example.com" in restored


def test_remap_empty_mapping_unchanged():
    restored = redactor.remap("Some LLM response", {})
    assert restored == "Some LLM response"


def test_remap_no_tokens_in_response_unchanged():
    mapping = {"EMAIL_ADDRESS_1": "john@example.com"}
    restored = redactor.remap("No tokens here", mapping)
    assert restored == "No tokens here"