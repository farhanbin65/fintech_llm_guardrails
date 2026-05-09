"""
Evaluation harness.

Runs the full attack corpus through the pipeline and measures:
  1. Block rate per vector (security effectiveness)
  2. Latency per request in ms (performance overhead)
  3. PII entity coverage (privacy effectiveness)

Outputs:
  - evaluation/results/benchmark_results.csv   (raw per-case data)
  - evaluation/results/summary.csv             (aggregated per vector)
  - Console summary table

Usage:
    python evaluation/run_benchmark.py
"""

import csv
import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from middleware.pipeline import GuardrailPipeline
from middleware.sanitiser import InputSanitiser
from middleware.separator import StructuralSeparator
from middleware.redactor import PIIRedactor
from middleware.output_validator import OutputValidator

_SHARED_SANITISER = InputSanitiser()
_SHARED_SEPARATOR = StructuralSeparator()
_SHARED_REDACTOR = PIIRedactor()
_SHARED_VALIDATOR = OutputValidator()


# ── Mock LLM ──────────────────────────────────────────────────────────────────

class ConfigurableMockLLM:
    def __init__(self, response: str):
        self.response = response

    def chat(self, messages):
        return self.response


DEFAULT_SAFE_RESPONSE = "You spent £120 on groceries last month."

# ── Config ────────────────────────────────────────────────────────────────────

CORPUS_FILES = [
    "tests/attacks/vector1_direct.json",
    "tests/attacks/vector2_transaction.json",
    "tests/attacks/vector3_csv.json",
    "tests/attacks/vector4_action.json",
    "tests/attacks/vector5_exfiltration.json",
]

RESULTS_DIR = "evaluation/results"
RUNS = 1


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class BenchmarkRecord:
    case_id: str
    vector: int
    run: int
    expected_blocked: bool
    actual_blocked: bool
    correct: bool
    block_layer: Optional[str]
    latency_ms: float
    entities_redacted: List[str]
    pii_present: bool
    notes: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_corpus() -> List[Dict]:
    cases = []
    for filepath in CORPUS_FILES:
        with open(filepath) as f:
            cases.extend(json.load(f))
    return cases


def run_case(case: Dict, run_number: int) -> BenchmarkRecord:
    llm_response = case.get("llm_response", DEFAULT_SAFE_RESPONSE)
    llm = ConfigurableMockLLM(llm_response)
    pipeline = GuardrailPipeline(
        llm_client=llm,
        sanitiser=_SHARED_SANITISER,
        separator=_SHARED_SEPARATOR,
        redactor=_SHARED_REDACTOR,
        validator=_SHARED_VALIDATOR,
    )

    start = time.monotonic()
    result = pipeline.process(
        user_message=case["user_message"],
        transactions=case.get("transactions", []),
    )
    latency_ms = (time.monotonic() - start) * 1000

    return BenchmarkRecord(
        case_id=case["id"],
        vector=case["vector"],
        run=run_number,
        expected_blocked=case["expected_blocked"],
        actual_blocked=result.blocked,
        correct=result.blocked == case["expected_blocked"],
        block_layer=result.block_layer,
        latency_ms=round(latency_ms, 2),
        entities_redacted=result.audit.entities_redacted,
        pii_present=case.get("pii_present", False),
        notes=case.get("notes", ""),
    )


# ── Aggregation ───────────────────────────────────────────────────────────────

def aggregate_by_vector(records: List[BenchmarkRecord]) -> Dict:
    vectors = sorted({r.vector for r in records})
    summary = {}

    for v in vectors:
        v_records = [r for r in records if r.vector == v]

        # Use run 1 only for correctness metrics (avoid counting same case N times)
        run1 = [r for r in v_records if r.run == 1]

        total = len(run1)
        correct = sum(1 for r in run1 if r.correct)
        blocked = sum(1 for r in run1 if r.actual_blocked)
        should_block = sum(1 for r in run1 if r.expected_blocked)
        pii_cases = [r for r in run1 if r.pii_present]
        pii_caught = [r for r in pii_cases if r.entities_redacted]

        # Latency across all runs for stable average
        latencies = [r.latency_ms for r in v_records]
        avg_latency = round(sum(latencies) / len(latencies), 2)
        max_latency = round(max(latencies), 2)
        min_latency = round(min(latencies), 2)

        summary[v] = {
            "vector": v,
            "total_cases": total,
            "correct": correct,
            "accuracy_pct": round((correct / total) * 100, 1) if total else 0,
            "blocked": blocked,
            "should_block": should_block,
            "block_rate_pct": round((blocked / should_block) * 100, 1) if should_block else 100.0,
            "pii_cases": len(pii_cases),
            "pii_caught": len(pii_caught),
            "pii_coverage_pct": round((len(pii_caught) / len(pii_cases)) * 100, 1) if pii_cases else None,
            "avg_latency_ms": avg_latency,
            "min_latency_ms": min_latency,
            "max_latency_ms": max_latency,
        }

    return summary


# ── CSV export ────────────────────────────────────────────────────────────────

def export_raw(records: List[BenchmarkRecord], path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "case_id", "vector", "run", "expected_blocked", "actual_blocked",
            "correct", "block_layer", "latency_ms", "entities_redacted",
            "pii_present", "notes",
        ])
        writer.writeheader()
        for r in records:
            writer.writerow({
                "case_id": r.case_id,
                "vector": r.vector,
                "run": r.run,
                "expected_blocked": r.expected_blocked,
                "actual_blocked": r.actual_blocked,
                "correct": r.correct,
                "block_layer": r.block_layer or "",
                "latency_ms": r.latency_ms,
                "entities_redacted": "|".join(r.entities_redacted),
                "pii_present": r.pii_present,
                "notes": r.notes,
            })


def export_summary(summary: Dict, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "vector", "total_cases", "correct", "accuracy_pct",
            "blocked", "should_block", "block_rate_pct",
            "pii_cases", "pii_caught", "pii_coverage_pct",
            "avg_latency_ms", "min_latency_ms", "max_latency_ms",
        ])
        writer.writeheader()
        for row in summary.values():
            writer.writerow(row)


# ── Console output ────────────────────────────────────────────────────────────

def print_summary(summary: Dict, total_records: int, total_correct: int):
    w = 72

    print(f"\n{'─'*w}")
    print(f"  Fintech LLM Guardrails — Evaluation Results ({RUNS} runs per case)")
    print(f"{'─'*w}")
    print(f"  {'V':<4} {'CASES':<7} {'ACCURACY':<11} {'BLOCK RATE':<13} "
          f"{'PII COV':<10} {'AVG MS':<9} {'MAX MS'}")
    print(f"{'─'*w}")

    for v, s in summary.items():
        pii_cov = f"{s['pii_coverage_pct']}%" if s['pii_coverage_pct'] is not None else "N/A"
        print(
            f"  {s['vector']:<4} {s['total_cases']:<7} "
            f"{s['accuracy_pct']}%{'':<7} "
            f"{s['block_rate_pct']}%{'':<9} "
            f"{pii_cov:<10} "
            f"{s['avg_latency_ms']:<9} "
            f"{s['max_latency_ms']}"
        )

    print(f"{'─'*w}")

    overall_accuracy = round((total_correct / total_records) * 100, 1)
    print(f"  Overall accuracy: {total_correct}/{total_records} ({overall_accuracy}%)")
    print(f"{'─'*w}\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def run_benchmark():
    print(f"\nLoading corpus...")
    cases = load_corpus()
    print(f"Loaded {len(cases)} cases. Running {RUNS} iterations each...\n")

    records: List[BenchmarkRecord] = []

    for run in range(1, RUNS + 1):
        for case in cases:
            record = run_case(case, run)
            records.append(record)
            status = "✓" if record.correct else "✗"
            print(f"  [{status}] {case['id']} run {run} — {record.latency_ms:.1f}ms")

    print(f"\nExporting results...")
    export_raw(records, f"{RESULTS_DIR}/benchmark_results.csv")

    summary = aggregate_by_vector(records)
    export_summary(summary, f"{RESULTS_DIR}/summary.csv")

    # Overall correctness across run 1 only
    run1_records = [r for r in records if r.run == 1]
    total_correct = sum(1 for r in run1_records if r.correct)

    print_summary(summary, len(run1_records), total_correct)

    print(f"  Raw results  → {RESULTS_DIR}/benchmark_results.csv")
    print(f"  Summary      → {RESULTS_DIR}/summary.csv\n")

    return total_correct == len(run1_records)


if __name__ == "__main__":
    success = run_benchmark()
    sys.exit(0 if success else 1)