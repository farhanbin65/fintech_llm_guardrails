"""
Pipeline: chains all four defence layers.
This is the single entry point your Flask routes call.
"""

from dataclasses import dataclass
from typing import List, Dict, Optional

from .sanitiser import InputSanitiser, SanitisationResult


@dataclass
class PipelineResult:
    response: Optional[str]
    blocked: bool
    block_reason: Optional[str]
    sanitisation: SanitisationResult


class GuardrailPipeline:
    def __init__(self, llm_client, sanitiser=None, separator=None, redactor=None, validator=None):
        self.llm = llm_client
        self.sanitiser = sanitiser or InputSanitiser()
        self.separator = separator           # Inject in Layer 2 PR
        self.redactor = redactor             # Inject in Layer 3 PR
        self.validator = validator           # Inject in Layer 4 PR

    def process(self, user_message: str, transactions: List[Dict]) -> PipelineResult:
        # Layer 1
        sanitisation = self.sanitiser.check(user_message)
        if sanitisation.is_suspicious:
            return PipelineResult(
                response=None,
                blocked=True,
                block_reason=f"Suspicious patterns: {sanitisation.matched_patterns}",
                sanitisation=sanitisation,
            )

        # Layers 2, 3, 4 will be wired in as you build them.
        # For now, a passthrough so you can verify Layer 1 end-to-end.
        response = self.llm.chat(user_message, transactions)
        return PipelineResult(
            response=response,
            blocked=False,
            block_reason=None,
            sanitisation=sanitisation,
        )