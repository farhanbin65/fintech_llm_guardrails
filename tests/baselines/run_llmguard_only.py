"""
LLM Guard isolated runner — run separately to avoid OOM when combined
with Presidio + our pipeline in the same process.

Saves results to evaluation/llmguard_results.json

Usage:
    python tests/baselines/run_llmguard_only.py
"""

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


def mean(lst):
    return sum(lst) / len(lst) if lst else 0.0

def median(lst):
    if not lst:
        return 0.0
    s = sorted(lst)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def main():
    attack_cases = []
    for f in ATTACK_FILES:
        with open(f) as fh:
            attack_cases.extend(json.load(fh))
    with open(FP_FILE) as f:
        fp_cases = json.load(f)

    true_attacks = [c for c in attack_cases if c["expected_blocked"]]
    print(f"LLM Guard isolated run")
    print(f"Attack cases: {len(attack_cases)} ({len(true_attacks)} expected-blocked)")
    print(f"Legit queries: {len(fp_cases)}\n")

    from llm_guard.input_scanners import PromptInjection
    scanner = PromptInjection(threshold=0.5)
    print("Model loaded. Running...\n")

    tp = 0
    fp = 0
    latencies = []

    for case in attack_cases:
        text = case["user_message"]
        for t in case.get("transactions", []):
            text += " " + t.get("description", "")

        try:
            t0 = time.perf_counter()
            _, is_valid, score = scanner.scan(prompt=text, output="")
            blocked = not is_valid
            latencies.append((time.perf_counter() - t0) * 1000)
        except Exception as e:
            blocked = False
            latencies.append(0.0)

        if case["expected_blocked"] and blocked:
            tp += 1

    for case in fp_cases:
        text = case["user_message"]
        try:
            t0 = time.perf_counter()
            _, is_valid, score = scanner.scan(prompt=text, output="")
            blocked = not is_valid
            latencies.append((time.perf_counter() - t0) * 1000)
        except Exception as e:
            blocked = False
            latencies.append(0.0)

        if blocked:
            fp += 1

    n_attacks = len(true_attacks)
    n_fp = len(fp_cases)

    print(f"{'─'*50}")
    print(f"  LLM Guard Results")
    print(f"{'─'*50}")
    print(f"  Block rate : {tp}/{n_attacks} ({(tp/n_attacks)*100:.1f}%)")
    print(f"  FP rate    : {fp}/{n_fp} ({(fp/n_fp)*100:.1f}%)")
    print(f"  Mean lat   : {mean(latencies):.1f}ms")
    print(f"  Median lat : {median(latencies):.1f}ms")
    print(f"{'─'*50}\n")

    out = {
        "block_rate_pct": round((tp / n_attacks) * 100, 1),
        "fp_rate_pct": round((fp / n_fp) * 100, 1),
        "mean_latency_ms": round(mean(latencies), 1),
        "median_latency_ms": round(median(latencies), 1),
        "tp": tp,
        "fp": fp,
        "n_attacks": n_attacks,
        "n_fp": n_fp,
    }
    os.makedirs("evaluation", exist_ok=True)
    with open("evaluation/llmguard_results.json", "w") as f:
        json.dump(out, f, indent=2)
    print("Saved → evaluation/llmguard_results.json")


if __name__ == "__main__":
    main()
    