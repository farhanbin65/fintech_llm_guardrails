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
from .provenance import ProvenanceTracker, ProvenanceReport, ProvenanceSource
from .risk_scorer import RiskScorer, RiskLevel, RiskScore
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
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    risk_signals: List[str] = field(default_factory=list)
    provenance_summary: Optional[str] = None          # ← ADD
    indirect_injection_detected: bool = False     


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
        sanitiser:        Optional[InputSanitiser]      = None,
        separator:        Optional[StructuralSeparator]  = None,
        redactor:         Optional[PIIRedactor]          = None,
        validator:        Optional[OutputValidator]       = None,
        risk_scorer:      Optional[RiskScorer]           = None,
        provenance:       Optional[ProvenanceTracker]    = None,   
    ):
        self.llm          = llm_client
        self.sanitiser    = sanitiser   or InputSanitiser()
        self.separator    = separator   or StructuralSeparator()
        self.redactor     = redactor    or PIIRedactor()
        self.validator    = validator   or OutputValidator()
        self.risk_scorer  = risk_scorer or RiskScorer()
        self.provenance   = provenance  or ProvenanceTracker()

    def process(
        self,
        user_message: str,
        transactions: Optional[List[Dict]] = None,
        source: str = "user",               
        session_id: Optional[str] = None,
        system_prompt: Optional[str] = None,
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
        risk = None

        try:
            # ── Layer 0a: Provenance tracking ─────────────────────────────────────
            provenance_report = self.provenance.analyse(
                user_message=user_message,
                transactions=transactions,
                system_prompt=system_prompt,
            )
            if provenance_report.indirect_injection_detected:
                return self._blocked(
                    start=start,
                    layer="Layer 0a — Provenance tracker",
                    reason=(
                        f"Indirect prompt injection detected in imported data. "
                        f"{provenance_report.summary}"
                    ),
                    sanitisation_flagged=False,
                    provenance_report=provenance_report,
                )
            source = provenance_report.highest_risk_source

            # ── Layer 0b: Risk scoring ─────────────────────────────────────────────
            risk = self.risk_scorer.score(
                user_message,
                source=source,
                session_id=session_id,
            )
            if risk.level == RiskLevel.HIGH:
                return self._blocked(
                    start=start,
                    layer="Layer 0b — Risk scorer",
                    reason=(
                        f"Risk score {risk.total} exceeded threshold. "
                        f"Signals: {risk.triggered_signals}"
                    ),
                    sanitisation_flagged=False,
                )

            # ── Layer 1: Input sanitisation ───────────────────────────────
            sanitisation = self.sanitiser.check(user_message)
            if sanitisation.is_suspicious:
                return self._blocked(
                    start=start,
                    layer="Layer 1 — Input sanitiser",
                    reason=f"Suspicious patterns detected: {sanitisation.matched_patterns}",
                    sanitisation_flagged=True,
                    risk=risk,
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
                    risk=risk,
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
                    risk_score=risk.total,
                    risk_level=risk.level.value,
                    risk_signals=list(risk.triggered_signals),
                    provenance_summary=(provenance_report.summary if 'provenance_report' in locals() else None),
                    indirect_injection_detected=(provenance_report.indirect_injection_detected
                                                 if 'provenance_report' in locals() else False),
                ),
            )

        except Exception as e:
            # Fail closed
            return self._blocked(
                start=start,
                layer="Pipeline",
                reason=f"Unhandled exception: {str(e)}",
                sanitisation_flagged=False,
                risk=risk,
            )
    

    def _blocked(
        self,
        start: float,
        layer: str,
        reason: str,
        sanitisation_flagged: bool,
        redaction_result: Optional[RedactionResult] = None,
        validation_result: Optional[ValidationResult] = None,
        risk: Optional["RiskScore"] = None, 
        provenance_report: Optional[ProvenanceReport] = None,
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
                risk_score=risk.total if risk else None,
                risk_level=risk.level.value if risk else None,
                risk_signals=list(risk.triggered_signals) if risk else [],
                provenance_summary=provenance_report.summary if provenance_report else None,
                indirect_injection_detected=(provenance_report.indirect_injection_detected
                                             if provenance_report else False),
            ),
        )