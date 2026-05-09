"""
Pipeline orchestrator.

Chains all four defence layers into a single entry point.
Called by Flask routes — this is the only middleware function
routes need to know about.

Flow:
    User message + transactions
        → Layer 1: input sanitisation
        → Layer 2: structural separation + prompt build
        → Layer 3: PII redaction
        → LLM API call
        → Layer 4: output validation
        → Layer 3: response re-mapping
        → Safe response to user

Fails closed: any unhandled exception blocks the request.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .sanitiser import InputSanitiser, SanitisationResult
from .separator import StructuralSeparator
from .redactor import PIIRedactor, RedactionResult
from .output_validator import OutputValidator, ValidationResult


# ── Audit log entry ───────────────────────────────────────────────────────────

@dataclass
class AuditEntry:
    """Single audit record for one request through the pipeline."""
    timestamp: float
    blocked: bool
    block_layer: Optional[str]
    block_reason: Optional[str]
    entities_redacted: List[str]
    latency_ms: float
    sanitisation_flagged: bool
    output_safe: bool


# ── Pipeline result ───────────────────────────────────────────────────────────

@dataclass
class PipelineResult:
    response: Optional[str]          # Final response to show the user
    blocked: bool                    # Was the request blocked?
    block_layer: Optional[str]       # Which layer blocked it?
    block_reason: Optional[str]      # Why was it blocked?
    audit: AuditEntry                # Full audit record
    redaction_result: Optional[RedactionResult] = None
    validation_result: Optional[ValidationResult] = None


# ── Pipeline ──────────────────────────────────────────────────────────────────

class GuardrailPipeline:

    def __init__(
        self,
        llm_client,
        sanitiser: Optional[InputSanitiser] = None,
        separator: Optional[StructuralSeparator] = None,
        redactor: Optional[PIIRedactor] = None,
        validator: Optional[OutputValidator] = None,
    ):
        self.llm = llm_client
        self.sanitiser = sanitiser or InputSanitiser()
        self.separator = separator or StructuralSeparator()
        self.redactor = redactor or PIIRedactor()
        self.validator = validator or OutputValidator()

    def process(
        self,
        user_message: str,
        transactions: Optional[List[Dict]] = None,
    ) -> PipelineResult:
        """
        Run user_message and transactions through the full four-layer pipeline.

        Args:
            user_message:  The raw message from the user.
            transactions:  List of transaction dicts from the DB.
                           Each should have: date, amount, description.

        Returns:
            PipelineResult with the safe response or a block reason.
        """
        start = time.monotonic()
        transactions = transactions or []

        try:
            # ── Layer 1: Input sanitisation ───────────────────────────────
            sanitisation = self.sanitiser.check(user_message)
            if sanitisation.is_suspicious:
                return self._blocked(
                    start=start,
                    layer="Layer 1 — Input sanitiser",
                    reason=f"Suspicious patterns detected: {sanitisation.matched_patterns}",
                    sanitisation_flagged=True,
                )

            # ── Layer 2: Structural separation ────────────────────────────
            messages = self.separator.build_messages(user_message, transactions)

            # ── Layer 3: PII redaction ────────────────────────────────────
            # Redact the user content block (index 1) only —
            # the system prompt is trusted and should not be modified.
            user_content = messages[1]["content"]
            redaction = self.redactor.redact(user_content)
            messages[1]["content"] = redaction.redacted_text

            # ── LLM API call ──────────────────────────────────────────────
            raw_response = self.llm.chat(messages)

            # ── Layer 4: Output validation ────────────────────────────────
            validation = self.validator.validate(
                raw_response,
                pii_mapping=redaction.mapping,
            )
            if not validation.is_safe:
                return self._blocked(
                    start=start,
                    layer="Layer 4 — Output validator",
                    reason=f"Unsafe response: {validation.reasons}",
                    sanitisation_flagged=False,
                    redaction_result=redaction,
                    validation_result=validation,
                )

            # ── Layer 3: Response re-mapping ──────────────────────────────
            final_response = self.redactor.remap(raw_response, redaction.mapping)

            latency_ms = (time.monotonic() - start) * 1000

            return PipelineResult(
                response=final_response,
                blocked=False,
                block_layer=None,
                block_reason=None,
                redaction_result=redaction,
                validation_result=validation,
                audit=AuditEntry(
                    timestamp=start,
                    blocked=False,
                    block_layer=None,
                    block_reason=None,
                    entities_redacted=redaction.entities_found,
                    latency_ms=round(latency_ms, 2),
                    sanitisation_flagged=False,
                    output_safe=True,
                ),
            )

        except Exception as e:
            # Fail closed
            return self._blocked(
                start=start,
                layer="Pipeline",
                reason=f"Unhandled exception: {str(e)}",
                sanitisation_flagged=False,
            )

    def _blocked(
        self,
        start: float,
        layer: str,
        reason: str,
        sanitisation_flagged: bool,
        redaction_result: Optional[RedactionResult] = None,
        validation_result: Optional[ValidationResult] = None,
    ) -> PipelineResult:
        latency_ms = (time.monotonic() - start) * 1000
        return PipelineResult(
            response=None,
            blocked=True,
            block_layer=layer,
            block_reason=reason,
            redaction_result=redaction_result,
            validation_result=validation_result,
            audit=AuditEntry(
                timestamp=start,
                blocked=True,
                block_layer=layer,
                block_reason=reason,
                entities_redacted=redaction_result.entities_found if redaction_result else [],
                latency_ms=round(latency_ms, 2),
                sanitisation_flagged=sanitisation_flagged,
                output_safe=False,
            ),
        )