"""
False Positive Runner — measures how often legitimate financial queries
are incorrectly blocked by the pipeline.

This is the primary usability evaluation axis for the paper.

Usage:
    python tests/false_positives/run_fp.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from fintech_llm_guard.pipeline import GuardrailPipeline


# ── Mock LLM ──────────────────────────────────────────────────────────────────

class SafeMockLLM:
    """Always returns a clean, safe response for FP testing."""
    def chat(self, messages):
        return "Based on your transactions, here is your spending summary."


# ── Runner ────────────────────────────────────────────────────────────────────

def run_fp():
    fp_file = "tests/false_positives/legitimate_queries.json"
    with open(fp_file) as f:
        cases = json.load(f)

    results = []
    false_positives = 0
    total = 0

    llm = SafeMockLLM()

    for case in cases:
        pipeline = GuardrailPipeline(llm_client=llm)
        result = pipeline.process(
            user_message=case["user_message"],
            transactions=case.get("transactions", []),
        )

        expected_blocked = case["expected_blocked"]
        actual_blocked = result.blocked
        is_fp = (not expected_blocked) and actual_blocked

        if is_fp:
            false_positives += 1

        total += 1
        results.append({
            "id": case["id"],
            "category": case["category"],
            "is_fp": is_fp,
            "blocked": actual_blocked,
            "block_layer": result.block_layer,
            "latency_ms": result.audit.latency_ms,
            "user_message": case["user_message"][:60],
            "notes": case.get("notes", ""),
        })

    fp_rate = (false_positives / total) * 100

    # ── Print summary ─────────────────────────────────────────────────────────
    print(f"\n{'─'*75}")
    print(f"  Fintech LLM Guardrails — False Positive Rate Evaluation")
    print(f"{'─'*75}")
    print(f"  {'ID':<10} {'CAT':<22} {'FP?':<5} {'BLOCKED':<8} {'LAYER':<30} {'MS'}")
    print(f"{'─'*75}")

    for r in results:
        layer = (r["block_layer"] or "—").replace("Layer ", "L").replace(" — ", " ")[:29]
        fp_flag = "*** FP" if r["is_fp"] else ""
        print(
            f"  {r['id']:<10} {r['category'][:21]:<22} {fp_flag:<5} "
            f"{'YES' if r['blocked'] else 'NO':<8} {layer:<30} "
            f"{r['latency_ms']:.1f}ms"
        )

    print(f"{'─'*75}")
    print(f"  Total queries : {total}")
    print(f"  False positives: {false_positives}")
    print(f"  FP rate        : {fp_rate:.1f}%")
    print(f"{'─'*75}\n")

    # ── Detail on any FPs ─────────────────────────────────────────────────────
    fps = [r for r in results if r["is_fp"]]
    if fps:
        print("  FALSE POSITIVE DETAILS:")
        for r in fps:
            print(f"  [{r['id']}] {r['user_message']}")
            print(f"         Layer: {r['block_layer']}")
            print(f"         Note:  {r['notes']}")
        print()

    return false_positives, total, fp_rate


if __name__ == "__main__":
    fp_count, total, rate = run_fp()
    sys.exit(0 if fp_count == 0 else 1)