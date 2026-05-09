"""
Layer 3: PII redactor.

Detects and pseudonymises PII in the prompt before the outbound LLM API call,
then re-maps pseudonyms back to original values in the returned response.

Uses Microsoft Presidio with custom recognisers for UK financial entities.

Defends against:
- PII leakage to third-party LLM providers (GDPR Article 25)
- Vector 5: PII exfiltration via crafted LLM response
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


# ── Custom UK financial entity recognisers ──────────────────────────────────

def build_uk_account_recogniser() -> PatternRecognizer:
    """UK bank account numbers — 8 digits."""
    return PatternRecognizer(
        supported_entity="UK_ACCOUNT_NUMBER",
        patterns=[Pattern(
            name="uk_account_number",
            regex=r"\b\d{8}\b",
            score=0.6,
        )],
        context=["account", "acc", "number"],
    )


def build_uk_sort_code_recogniser() -> PatternRecognizer:
    """UK sort codes — XX-XX-XX or XXXXXX."""
    return PatternRecognizer(
        supported_entity="UK_SORT_CODE",
        patterns=[
            Pattern(
                name="uk_sort_code_dashes",
                regex=r"\b\d{2}-\d{2}-\d{2}\b",
                score=0.85,
            ),
            Pattern(
                name="uk_sort_code_plain",
                regex=r"\b\d{6}\b",
                score=0.5,
            ),
        ],
        context=["sort", "sortcode", "sort-code", "sort code"],
    )


def build_iban_recogniser() -> PatternRecognizer:
    """IBAN — GB + 2 digits + 4 letters + 14 digits."""
    return PatternRecognizer(
        supported_entity="IBAN",
        patterns=[Pattern(
            name="iban",
            regex=r"\bGB\d{2}[A-Z]{4}\d{14}\b",
            score=0.95,
        )],
    )


def build_uk_ni_recogniser() -> PatternRecognizer:
    """UK National Insurance numbers."""
    return PatternRecognizer(
        supported_entity="UK_NI_NUMBER",
        patterns=[Pattern(
            name="uk_ni_number",
            regex=r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b",
            score=0.9,
        )],
        context=["national insurance", "ni number", "nino"],
    )


def build_transaction_id_recogniser() -> PatternRecognizer:
    """Common transaction/reference ID patterns."""
    return PatternRecognizer(
        supported_entity="TRANSACTION_ID",
        patterns=[Pattern(
            name="transaction_id",
            regex=r"\b(TXN|REF|TRX|PAY)[A-Z0-9]{6,20}\b",
            score=0.85,
        )],
    )


# ── Redaction session ────────────────────────────────────────────────────────

@dataclass
class RedactionResult:
    redacted_text: str
    mapping: Dict[str, str]          # token → original value
    entities_found: List[str]        # entity types detected


class PIIRedactor:
    """
    Detects and pseudonymises PII using Presidio.
    Maintains a per-request mapping table for response re-mapping.
    """

    # Entity types Presidio detects out of the box that we want to catch
    DEFAULT_ENTITIES = [
        "PERSON",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CREDIT_CARD",
        "IBAN_CODE",
        "UK_NHS",
        # Custom
        "UK_ACCOUNT_NUMBER",
        "UK_SORT_CODE",
        "IBAN",
        "UK_NI_NUMBER",
        "TRANSACTION_ID",
    ]

    def __init__(self, entities: Optional[List[str]] = None):
        self.entities = entities or self.DEFAULT_ENTITIES
        self._analyser = self._build_analyser()
        self._anonymiser = AnonymizerEngine()
        # Counter per entity type for consistent token naming
        self._counters: Dict[str, int] = {}

    def _build_analyser(self) -> AnalyzerEngine:
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
        })
        nlp_engine = provider.create_engine()
        analyser = AnalyzerEngine(nlp_engine=nlp_engine)

        # Register custom UK financial recognisers
        for recogniser in [
            build_uk_account_recogniser(),
            build_uk_sort_code_recogniser(),
            build_uk_ni_recogniser(),
            build_transaction_id_recogniser(),
        ]:
            analyser.registry.add_recognizer(recogniser)

        return analyser

    def _make_token(self, entity_type: str) -> str:
        """Generate a consistent, readable token e.g. PERSON_1, ACCOUNT_2."""
        self._counters[entity_type] = self._counters.get(entity_type, 0) + 1
        return f"{entity_type}_{self._counters[entity_type]}"

    def redact(self, text: str) -> RedactionResult:
        """
        Analyse text, replace PII with tokens, return result + mapping.
        Counters reset per call — each request gets its own fresh mapping.
        """
        self._counters = {}

        results = self._analyser.analyze(
            text=text,
            entities=self.entities,
            language="en",
        )

        if not results:
            return RedactionResult(
                redacted_text=text,
                mapping={},
                entities_found=[],
            )

        # Build a mapping: token → original span text
        mapping: Dict[str, str] = {}
        operators: Dict[str, OperatorConfig] = {}

        for result in results:
            token = self._make_token(result.entity_type)
            original = text[result.start:result.end]
            mapping[token] = original
            operators[result.entity_type] = OperatorConfig(
                "replace", {"new_value": token}
            )

        anonymised = self._anonymiser.anonymize(
            text=text,
            analyzer_results=results,
            operators=operators,
        )

        return RedactionResult(
            redacted_text=anonymised.text,
            mapping=mapping,
            entities_found=list({r.entity_type for r in results}),
        )

    def remap(self, text: str, mapping: Dict[str, str]) -> str:
        """
        Replace tokens in the LLM response with their original values.
        Tokens are replaced longest-first to avoid partial matches.
        """
        if not mapping:
            return text

        result = text
        for token, original in sorted(mapping.items(), key=lambda x: -len(x[0])):
            result = result.replace(token, original)
        return result