"""LLM Guard isolated baseline — isolated process."""
import json, os, sys, time
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

def mean(lst): return sum(lst)/len(lst) if lst else 0.0
def median(lst):
    if not lst: return 0.0
    s = sorted(lst); n = len(s)
    return s[n//2] if n%2 else (s[n//2-1]+s[n//2])/2

def scan(scanner, text):
    try:
        result = scanner.scan(prompt=text)
        if isinstance(result, tuple) and len(result) == 3:
            _, is_valid, _ = result
            return not is_valid
    except TypeError:
        pass
    try:
        _, is_valid, _ = scanner.scan(prompt=text, output="")
        return not is_valid
    except Exception:
        pass
    return False

def main():
    attack_cases = []
    for f in ATTACK_FILES:
        with open(f) as fh: attack_cases.extend(json.load(fh))
    with open(FP_FILE) as f: fp_cases = json.load(f)

    true_attacks = [c for c in attack_cases if c["expected_blocked"]]
    print(f"LLM Guard isolated run")
    print(f"Attack cases: {len(attack_cases)} ({len(true_attacks)} expected-blocked)")
    print(f"Legit queries: {len(fp_cases)}\n")

    from llm_guard.input_scanners import PromptInjection
    scanner = PromptInjection(threshold=0.5)
    print("Model loaded. Running...\n")
    scan(scanner, "warm up")

    tp, fp, latencies = 0, 0, []

    for case in attack_cases:
        text = case["user_message"]
        for t in case.get("transactions", []): text += " " + t.get("description", "")
        t0 = time.perf_counter()
        blocked = scan(scanner, text)
        latencies.append((time.perf_counter()-t0)*1000)
        if case["expected_blocked"] and blocked: tp += 1

    for case in fp_cases:
        text = case["user_message"]
        t0 = time.perf_counter()
        blocked = scan(scanner, text)
        latencies.append((time.perf_counter()-t0)*1000)
        if blocked: fp += 1

    n_a, n_f = len(true_attacks), len(fp_cases)
    print(f"{'─'*50}")
    print(f"  LLM Guard Results")
    print(f"{'─'*50}")
    print(f"  Block rate : {tp}/{n_a} ({tp/n_a*100:.1f}%)")
    print(f"  FP rate    : {fp}/{n_f} ({fp/n_f*100:.1f}%)")
    print(f"  Mean lat   : {mean(latencies):.1f}ms")
    print(f"  Median lat : {median(latencies):.1f}ms")
    print(f"{'─'*50}\n")

    os.makedirs("evaluation", exist_ok=True)
    with open("evaluation/llmguard_results.json", "w") as f:
        json.dump({
            "block_rate_pct": round(tp/n_a*100, 1),
            "fp_rate_pct": round(fp/n_f*100, 1),
            "mean_latency_ms": round(mean(latencies), 1),
            "median_latency_ms": round(median(latencies), 1),
            "tp": tp, "fp": fp, "n_attacks": n_a, "n_fp": n_f,
        }, f, indent=2)
    print("Saved → evaluation/llmguard_results.json")

if __name__ == "__main__": main()