"""
Baseline comparison runner.

Evaluates three systems on the same 107-case attack corpus and 60-case
legitimate query set, producing a side-by-side comparison table.

Systems:
  1. Presidio standalone   — PII detection only, no injection defence
  2. LLM Guard             — PromptInjection scanner (DeBERTa-v3)
  3. Fintech LLM Guard     — this project (all 4 layers)

Usage:
    python tests/baselines/run_baselines.py [--skip-llmguard]
"""

import argparse
import gc
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

ATTACK_FILES = [
    "tests/attacks/vector1_direct.json",
    "tests/attacks/vector2_transaction.json",
    "tests/attacks/vector3_csv.json",
    "tests/attacks/vector4_action.json",
    "tests/attacks/vector5_exfiltration.json",
    "tests/attacks/vector6_obfuscated.json",
    "tests/attacks/vector7_pii_direct.json",
    "tests/attacks/vector8_context.json",
]
FP_FILE = "tests/false_positives/legitimate_queries.json"


def load_corpora():
    cases = []
    for f in ATTACK_FILES:
        with open(f) as fh:
            cases.extend(json.load(fh))
    with open(FP_FILE) as f:
        fp_cases = json.load(f)
    return cases, fp_cases


def mean(lst):
    return sum(lst) / len(lst) if lst else 0.0

def median(lst):
    if not lst:
        return 0.0
    s = sorted(lst)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


# ── System 1: Presidio standalone ────────────────────────────────────────────

def run_presidio(attack_cases, fp_cases):
    print("[1/3] Running Presidio standalone...")
    from presidio_analyzer import AnalyzerEngine
    analyzer = AnalyzerEngine()

    results = {"tp": 0, "fp": 0, "latencies": []}

    for case in attack_cases:
        text = case["user_message"]
        for t in case.get("transactions", []):
            text += " " + t.get("description", "")
        text += " " + case.get("llm_response", "")

        t0 = time.perf_counter()
        found = analyzer.analyze(text=text, language="en")
        blocked = len(found) > 0
        results["latencies"].append((time.perf_counter() - t0) * 1000)

        if case["expected_blocked"] and blocked:
            results["tp"] += 1

    for case in fp_cases:
        text = case["user_message"]
        for t in case.get("transactions", []):
            text += " " + t.get("description", "")

        t0 = time.perf_counter()
        found = analyzer.analyze(text=text, language="en")
        blocked = len(found) > 0
        results["latencies"].append((time.perf_counter() - t0) * 1000)

        if blocked:
            results["fp"] += 1

    del analyzer
    gc.collect()
    return results


# ── System 2: LLM Guard ───────────────────────────────────────────────────────

def run_llm_guard(attack_cases, fp_cases):
    print("[2/3] Running LLM Guard (PromptInjection scanner)...")
    try:
        from llm_guard.input_scanners import PromptInjection
        scanner = PromptInjection(threshold=0.5)
    except Exception as e:
        print(f"  LLM Guard init failed: {e}")
        return None

    results = {"tp": 0, "fp": 0, "latencies": []}

    for case in attack_cases:
        text = case["user_message"]
        for t in case.get("transactions", []):
            text += " " + t.get("description", "")

        try:
            t0 = time.perf_counter()
            _, is_valid, _ = scanner.scan(prompt=text, output="")
            blocked = not is_valid
            results["latencies"].append((time.perf_counter() - t0) * 1000)
        except Exception:
            blocked = False
            results["latencies"].append(0.0)

        if case["expected_blocked"] and blocked:
            results["tp"] += 1

    for case in fp_cases:
        text = case["user_message"]
        try:
            t0 = time.perf_counter()
            _, is_valid, _ = scanner.scan(prompt=text, output="")
            blocked = not is_valid
            results["latencies"].append((time.perf_counter() - t0) * 1000)
        except Exception:
            blocked = False
            results["latencies"].append(0.0)

        if blocked:
            results["fp"] += 1

    del scanner
    gc.collect()
    return results


# ── System 3: Fintech LLM Guard ───────────────────────────────────────────────

def run_our_system(attack_cases, fp_cases):
    print("[3/3] Running Fintech LLM Guard...")
    from middleware.pipeline import GuardrailPipeline

    class SafeMockLLM:
        def chat(self, messages):
            return "Based on your transactions, here is your spending summary."

    class ConfigurableMockLLM:
        def __init__(self, response):
            self.response = response
        def chat(self, messages):
            return self.response

    DEFAULT_SAFE = "You spent £120 on groceries last month."
    results = {"tp": 0, "fp": 0, "latencies": []}

    for case in attack_cases:
        llm = ConfigurableMockLLM(case.get("llm_response", DEFAULT_SAFE))
        pipeline = GuardrailPipeline(llm_client=llm)

        t0 = time.perf_counter()
        result = pipeline.process(
            user_message=case["user_message"],
            transactions=case.get("transactions", []),
        )
        results["latencies"].append((time.perf_counter() - t0) * 1000)

        if case["expected_blocked"] and result.blocked:
            results["tp"] += 1

    for case in fp_cases:
        llm = SafeMockLLM()
        pipeline = GuardrailPipeline(llm_client=llm)

        t0 = time.perf_counter()
        result = pipeline.process(
            user_message=case["user_message"],
            transactions=case.get("transactions", []),
        )
        results["latencies"].append((time.perf_counter() - t0) * 1000)

        if result.blocked:
            results["fp"] += 1

    return results


# ── Print table ───────────────────────────────────────────────────────────────

def print_table(attack_cases, fp_cases, presidio, llmg, ours):
    true_attacks = [c for c in attack_cases if c["expected_blocked"]]
    n_attacks = len(true_attacks)
    n_fp = len(fp_cases)

    def pct(n, d):
        return f"{(n/d)*100:.1f}%" if d else "N/A"

    llmg_ok = llmg is not None

    print(f"\n{'═'*74}")
    print(f"  BASELINE COMPARISON TABLE")
    print(f"{'═'*74}")
    print(f"  {'Metric':<36} {'Presidio':>10} {'LLM Guard':>11} {'Ours':>10}")
    print(f"{'─'*74}")
    print(f"  {'Attack block rate':<36} "
          f"{pct(presidio['tp'], n_attacks):>10} "
          f"{pct(llmg['tp'], n_attacks) if llmg_ok else 'SKIP':>11} "
          f"{pct(ours['tp'], n_attacks):>10}")
    print(f"  {'Attacks blocked (n / {n_attacks})':<36} "
          f"{presidio['tp']:>10} "
          f"{llmg['tp'] if llmg_ok else '—':>11} "
          f"{ours['tp']:>10}")
    print(f"{'─'*74}")
    print(f"  {'False positive rate':<36} "
          f"{pct(presidio['fp'], n_fp):>10} "
          f"{pct(llmg['fp'], n_fp) if llmg_ok else 'SKIP':>11} "
          f"{pct(ours['fp'], n_fp):>10}")
    print(f"  {'FP count (n / {n_fp} legit queries)':<36} "
          f"{presidio['fp']:>10} "
          f"{llmg['fp'] if llmg_ok else '—':>11} "
          f"{ours['fp']:>10}")
    print(f"{'─'*74}")
    print(f"  {'Mean latency (ms)':<36} "
          f"{mean(presidio['latencies']):>9.1f}ms "
          f"{mean(llmg['latencies']):>10.1f}ms " if llmg_ok else f"{'—':>11} "
          f"{mean(ours['latencies']):>9.1f}ms")
    print(f"  {'Median latency (ms)':<36} "
          f"{median(presidio['latencies']):>9.1f}ms "
          f"{median(llmg['latencies']):>10.1f}ms " if llmg_ok else f"{'—':>11} "
          f"{median(ours['latencies']):>9.1f}ms")
    print(f"{'─'*74}")
    print(f"  {'PII redaction':<36} {'Yes':>10} {'No':>11} {'Yes':>10}")
    print(f"  {'Prompt injection defence':<36} {'No':>10} {'Yes':>11} {'Yes':>10}")
    print(f"  {'Output/response validation':<36} {'No':>10} {'No':>11} {'Yes':>10}")
    print(f"  {'Fintech-specific PII entities':<36} {'No':>10} {'No':>11} {'Yes':>10}")
    print(f"  {'PII response re-mapping':<36} {'No':>10} {'No':>11} {'Yes':>10}")
    print(f"{'═'*74}\n")

    # Save JSON
    out = {
        "corpus": {
            "total_attack_cases": len(attack_cases),
            "expected_blocked_cases": n_attacks,
            "legitimate_query_cases": n_fp,
        },
        "presidio": {
            "block_rate_pct": round((presidio["tp"] / n_attacks) * 100, 1),
            "fp_rate_pct": round((presidio["fp"] / n_fp) * 100, 1),
            "mean_latency_ms": round(mean(presidio["latencies"]), 1),
            "median_latency_ms": round(median(presidio["latencies"]), 1),
        },
        "llm_guard": {
            "block_rate_pct": round((llmg["tp"] / n_attacks) * 100, 1) if llmg_ok else None,
            "fp_rate_pct": round((llmg["fp"] / n_fp) * 100, 1) if llmg_ok else None,
            "mean_latency_ms": round(mean(llmg["latencies"]), 1) if llmg_ok else None,
            "median_latency_ms": round(median(llmg["latencies"]), 1) if llmg_ok else None,
        },
        "fintech_llm_guard": {
            "block_rate_pct": round((ours["tp"] / n_attacks) * 100, 1),
            "fp_rate_pct": round((ours["fp"] / n_fp) * 100, 1),
            "mean_latency_ms": round(mean(ours["latencies"]), 1),
            "median_latency_ms": round(median(ours["latencies"]), 1),
        },
    }
    os.makedirs("evaluation", exist_ok=True)
    with open("evaluation/baseline_results.json", "w") as f:
        json.dump(out, f, indent=2)
    print("  Saved → evaluation/baseline_results.json")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-llmguard", action="store_true",
                        help="Skip LLM Guard (saves ~1GB RAM, use if OOM killed)")
    args = parser.parse_args()

    attack_cases, fp_cases = load_corpora()
    true_attacks = [c for c in attack_cases if c["expected_blocked"]]
    print(f"Corpus: {len(attack_cases)} attack cases ({len(true_attacks)} expected-blocked), "
          f"{len(fp_cases)} legitimate queries\n")

    presidio = run_presidio(attack_cases, fp_cases)

    if args.skip_llmguard:
        print("[2/3] LLM Guard — skipped (--skip-llmguard)")
        llmg = {"tp": 0, "fp": 0, "latencies": [0.0]}
        llmg = None
    else:
        llmg = run_llm_guard(attack_cases, fp_cases)

    ours = run_our_system(attack_cases, fp_cases)
    print_table(attack_cases, fp_cases, presidio, llmg, ours)


if __name__ == "__main__":
    main()