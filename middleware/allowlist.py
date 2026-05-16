"""
Layer 4b: Tool/Action Allowlist Engine.

Enforces a strict declarative allowlist of permitted actions that the
LLM may propose. The LLM suggests; this layer decides.

Design principle:
    No action outside the allowlist can ever be approved, regardless
    of how the LLM frames the request. The registry is defined at
    startup and is immutable at runtime.

Threat modelled:
    - Action hijacking via prompt injection (Vector 4)
    - LLM proposing financial operations not requested by the user
    - Parameter manipulation (e.g. injected account numbers in transfer calls)
    - Privilege escalation via plausible-sounding action names

Integration:
    The pipeline calls AllowlistEngine.validate_proposal() after the
    LLM response is received but before any action is executed.
    Text-only responses (no action proposal) bypass this layer.

Fintech action registry:
    Only read-only and analytical actions are permitted by default.
    Any action that modifies state (transfers, deletions, updates)
    requires explicit human confirmation and is marked
    requires_confirmation=True.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


# ── Action risk tiers ─────────────────────────────────────────────────────────

class ActionRisk(Enum):
    LOW    = "low"     # Read-only, no state change
    MEDIUM = "medium"  # Writes metadata, no financial state change
    HIGH   = "high"    # Modifies financial state — requires confirmation


# ── Registered action definition ─────────────────────────────────────────────

@dataclass
class AllowedAction:
    """
    A single registered action in the allowlist.

    Attributes:
        name:                 Unique action identifier.
        description:          Human-readable description (for audit logs).
        risk:                 Risk tier of this action.
        allowed_params:       Set of parameter names this action accepts.
        required_params:      Subset of allowed_params that must be present.
        requires_confirmation: If True, a human must confirm before execution.
        param_validators:     Optional dict of param_name → validator function.
                              Validator returns True if the value is acceptable.
    """
    name:                 str
    description:          str
    risk:                 ActionRisk
    allowed_params:       set
    required_params:      set = field(default_factory=set)
    requires_confirmation: bool = False
    param_validators:     Dict[str, Callable[[Any], bool]] = field(
        default_factory=dict
    )


# ── Action proposal (from LLM) ────────────────────────────────────────────────

@dataclass
class ActionProposal:
    """
    A structured action proposed by the LLM.

    In production this would be parsed from a tool-use / function-call
    block in the LLM response. For this proof-of-concept, proposals
    are constructed programmatically from parsed response content.

    Attributes:
        action_name:  The name of the action the LLM wants to invoke.
        params:       Key-value parameters extracted from the proposal.
        raw_response: The original LLM response text for audit purposes.
    """
    action_name:  str
    params:       Dict[str, Any] = field(default_factory=dict)
    raw_response: str = ""


# ── Validation result ─────────────────────────────────────────────────────────

@dataclass
class ActionResult:
    """
    Result of allowlist validation for a single proposal.

    Attributes:
        approved:             True if the action may proceed.
        action_name:          The proposed action name.
        risk:                 Risk tier if approved, else None.
        requires_confirmation: Whether human confirmation is needed.
        denial_reason:        Populated if approved=False.
        invalid_params:       List of param names that failed validation.
        audit_note:           Summary string for audit log.
    """
    approved:              bool
    action_name:           str
    risk:                  Optional[ActionRisk] = None
    requires_confirmation: bool = False
    denial_reason:         Optional[str] = None
    invalid_params:        List[str] = field(default_factory=list)
    audit_note:            str = ""


# ── Default fintech action registry ──────────────────────────────────────────

def _positive_amount(v: Any) -> bool:
    """Validator: value must be a positive number."""
    try:
        return float(v) > 0
    except (TypeError, ValueError):
        return False


def _safe_string(v: Any) -> bool:
    """Validator: no injection-like content in string parameters."""
    if not isinstance(v, str):
        return False
    injection_pattern = re.compile(
        r"(ignore|override|system|instructions?|transfer|exfiltrate)",
        re.IGNORECASE,
    )
    return not injection_pattern.search(v)


def _valid_category(v: Any) -> bool:
    """Validator: must be one of the recognised spending categories."""
    allowed = {
        "groceries", "transport", "utilities", "entertainment",
        "dining", "healthcare", "shopping", "subscriptions",
        "income", "transfer", "other",
    }
    return isinstance(v, str) and v.lower() in allowed


def _valid_period(v: Any) -> bool:
    """Validator: must be a recognised reporting period."""
    allowed = {"daily", "weekly", "monthly", "quarterly", "yearly"}
    return isinstance(v, str) and v.lower() in allowed


DEFAULT_FINTECH_ACTIONS: List[AllowedAction] = [

    # ── Read-only actions (LOW risk) ──────────────────────────────────────

    AllowedAction(
        name="get_spending_summary",
        description="Retrieve a read-only summary of spending for a period.",
        risk=ActionRisk.LOW,
        allowed_params={"period", "category"},
        required_params={"period"},
        param_validators={
            "period":   _valid_period,
            "category": _valid_category,
        },
    ),

    AllowedAction(
        name="get_transaction_list",
        description="Retrieve a list of transactions with optional filters.",
        risk=ActionRisk.LOW,
        allowed_params={"limit", "category", "start_date", "end_date"},
        param_validators={
            "category": _valid_category,
            "limit": lambda v: isinstance(v, int) and 1 <= v <= 100,
        },
    ),

    AllowedAction(
        name="get_balance",
        description="Retrieve the current account balance.",
        risk=ActionRisk.LOW,
        allowed_params=set(),
    ),

    AllowedAction(
        name="get_budget_status",
        description="Check spending against set budget limits.",
        risk=ActionRisk.LOW,
        allowed_params={"category"},
        param_validators={"category": _valid_category},
    ),

    AllowedAction(
        name="get_recurring_transactions",
        description="Identify recurring charges and subscriptions.",
        risk=ActionRisk.LOW,
        allowed_params=set(),
    ),

    # ── Metadata write actions (MEDIUM risk) ──────────────────────────────

    AllowedAction(
        name="categorise_transaction",
        description="Update the category label on a single transaction.",
        risk=ActionRisk.MEDIUM,
        allowed_params={"transaction_id", "category"},
        required_params={"transaction_id", "category"},
        param_validators={
            "transaction_id": _safe_string,
            "category":       _valid_category,
        },
    ),

    AllowedAction(
        name="flag_suspicious_transaction",
        description="Mark a transaction as suspicious for human review.",
        risk=ActionRisk.MEDIUM,
        allowed_params={"transaction_id", "reason"},
        required_params={"transaction_id"},
        param_validators={
            "transaction_id": _safe_string,
            "reason":         _safe_string,
        },
    ),

    # ── Financial state actions (HIGH risk — confirmation required) ───────

    AllowedAction(
        name="set_budget_limit",
        description="Update a spending budget limit for a category.",
        risk=ActionRisk.HIGH,
        allowed_params={"category", "amount"},
        required_params={"category", "amount"},
        requires_confirmation=True,
        param_validators={
            "category": _valid_category,
            "amount":   _positive_amount,
        },
    ),

    AllowedAction(
        name="export_report",
        description="Generate and export a spending report.",
        risk=ActionRisk.HIGH,
        allowed_params={"period", "format"},
        required_params={"period"},
        requires_confirmation=True,
        param_validators={
            "period": _valid_period,
            "format": lambda v: v in {"pdf", "csv"},
        },
    ),
]


# ── Allowlist engine ──────────────────────────────────────────────────────────

class AllowlistEngine:
    """
    Validates LLM-proposed actions against a declarative allowlist.

    Usage:
        engine = AllowlistEngine()   # uses DEFAULT_FINTECH_ACTIONS

        proposal = ActionProposal(
            action_name="get_spending_summary",
            params={"period": "monthly"},
        )
        result = engine.validate_proposal(proposal)

        if result.approved and not result.requires_confirmation:
            execute_action(proposal)
        elif result.approved and result.requires_confirmation:
            request_human_confirmation(proposal)
        else:
            block_and_log(result.denial_reason)
    """

    def __init__(self, actions: Optional[List[AllowedAction]] = None):
        self._registry: Dict[str, AllowedAction] = {
            a.name: a for a in (actions or DEFAULT_FINTECH_ACTIONS)
        }

    # ── Public API ────────────────────────────────────────────────────────────

    def validate_proposal(self, proposal: ActionProposal) -> ActionResult:
        """
        Validate a single action proposal.

        Checks (in order):
            1. Action name is on the allowlist
            2. No unknown parameters present
            3. All required parameters present
            4. All parameter values pass their validators

        Returns:
            ActionResult — approved or denied with full reasoning.
        """
        action = self._registry.get(proposal.action_name)

        # ── Check 1: action must be registered ───────────────────────────
        if action is None:
            return ActionResult(
                approved=False,
                action_name=proposal.action_name,
                denial_reason=(
                    f"Action '{proposal.action_name}' is not on the allowlist. "
                    f"Permitted actions: {sorted(self._registry.keys())}"
                ),
                audit_note=(
                    f"DENIED — unknown action '{proposal.action_name}'"
                ),
            )

        invalid_params: List[str] = []

        # ── Check 2: no unknown parameters ───────────────────────────────
        unknown = set(proposal.params.keys()) - action.allowed_params
        if unknown:
            return ActionResult(
                approved=False,
                action_name=proposal.action_name,
                denial_reason=(
                    f"Unknown parameters for '{proposal.action_name}': {unknown}. "
                    f"Allowed: {action.allowed_params}"
                ),
                audit_note=f"DENIED — unknown params {unknown}",
            )

        # ── Check 3: required parameters present ─────────────────────────
        missing = action.required_params - set(proposal.params.keys())
        if missing:
            return ActionResult(
                approved=False,
                action_name=proposal.action_name,
                denial_reason=(
                    f"Missing required parameters for '{proposal.action_name}': {missing}"
                ),
                audit_note=f"DENIED — missing required params {missing}",
            )

        # ── Check 4: parameter value validation ───────────────────────────
        for param, value in proposal.params.items():
            validator = action.param_validators.get(param)
            if validator and not validator(value):
                invalid_params.append(param)

        if invalid_params:
            return ActionResult(
                approved=False,
                action_name=proposal.action_name,
                denial_reason=(
                    f"Invalid parameter values for '{proposal.action_name}': "
                    f"{invalid_params}"
                ),
                invalid_params=invalid_params,
                audit_note=f"DENIED — invalid param values {invalid_params}",
            )

        # ── Approved ──────────────────────────────────────────────────────
        confirmation_note = (
            " — REQUIRES HUMAN CONFIRMATION" if action.requires_confirmation else ""
        )
        return ActionResult(
            approved=True,
            action_name=proposal.action_name,
            risk=action.risk,
            requires_confirmation=action.requires_confirmation,
            audit_note=(
                f"APPROVED [{action.risk.value.upper()}]{confirmation_note} "
                f"— '{proposal.action_name}' params={proposal.params}"
            ),
        )

    def registered_actions(self) -> List[str]:
        """Return sorted list of all registered action names."""
        return sorted(self._registry.keys())

    def is_registered(self, action_name: str) -> bool:
        """Check if an action name is on the allowlist."""
        return action_name in self._registry