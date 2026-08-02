"""
Corpus runner — validates every attack case against the pipeline.
Produces a summary showing pass/fail per vector.

Usage:
    python tests/attacks/run_corpus.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from fintech_llm_guard.pipeline import GuardrailPipeline


# ── Mock LLM ──────────────────────────────────────────────────────────────────

class ConfigurableMockLLM:
    """Returns a specific response configured per test case."""
    def __init__(self, response: str):
        self.response = response

    def chat(self, messages):
        return self.response


DEFAULT_SAFE_RESPONSE = "You spent £120 on groceries last month."


# ── Corpus files ──────────────────────────────────────────────────────────────

CORPUS_FILES = [
    "tests/attacks/vector1_direct.json",
    "tests/attacks/vector2_transaction.json",
    "tests/attacks/vector3_csv.json",
    "tests/attacks/vector4_action.json",
    "tests/attacks/vector5_exfiltration.json",
    "tests/attacks/vector6_obfuscated.json",
    "tests/attacks/vector7_pii_direct.json",
    "tests/attacks/vector8_context.json",
]


# ── Runner ────────────────────────────────────────────────────────────────────

def run_corpus():
    results = []
    passed = 0
    failed = 0

    for filepath in CORPUS_FILES:
        with open(filepath) as f:
            cases = json.load(f)

        for case in cases:
            vector = case["vector"]  

            llm_response = case.get("llm_response", DEFAULT_SAFE_RESPONSE)
            llm = ConfigurableMockLLM(llm_response)
            pipeline = GuardrailPipeline(llm_client=llm)

            result = pipeline.process(
                user_message=case["user_message"],
                transactions=case.get("transactions", []),
            )

            expected_blocked = case["expected_blocked"]
            actual_blocked = result.blocked

            status = "PASS" if expected_blocked == actual_blocked else "FAIL"
            if status == "PASS":
                passed += 1
            else:
                failed += 1

            results.append({
                "id": case["id"],
                "vector": vector,
                "status": status,
                "expected_blocked": expected_blocked,
                "actual_blocked": actual_blocked,
                "block_layer": result.block_layer,
                "latency_ms": result.audit.latency_ms,
                "entities_redacted": result.audit.entities_redacted,
                "notes": case.get("notes", ""),
            })

    # ── Print summary ─────────────────────────────────────────────────────────
    print(f"\n{'─'*70}")
    print(f"  Fintech LLM Guardrails — Attack Corpus Results")
    print(f"{'─'*70}")
    print(f"  {'ID':<10} {'V':<4} {'STATUS':<6} {'BLOCKED':<9} {'LAYER':<35} {'MS'}")
    print(f"{'─'*70}")

    for r in results:
        layer = r["block_layer"] or "—"
        layer_short = layer.replace("Layer ", "L").replace(" — ", " ")[:34]
        print(
            f"  {r['id']:<10} {r['vector']:<4} {r['status']:<6} "
            f"{'YES' if r['actual_blocked'] else 'NO':<9} "
            f"{layer_short:<35} {r['latency_ms']:.1f}ms"
        )

    print(f"{'─'*70}")
    print(f"  PASSED: {passed}  FAILED: {failed}  TOTAL: {passed + failed}")
    print(f"{'─'*70}\n")

    return failed == 0


if __name__ == "__main__":
    success = run_corpus()
    sys.exit(0 if success else 1)