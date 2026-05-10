"""Presidio standalone baseline — isolated process."""
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

def main():
    attack_cases = []
    for f in ATTACK_FILES:
        with open(f) as fh: attack_cases.extend(json.load(fh))
    with open(FP_FILE) as f: fp_cases = json.load(f)

    print(f"Presidio standalone — {len(attack_cases)} cases, {len(fp_cases)} legit queries\n")

    from presidio_analyzer import AnalyzerEngine
    analyzer = AnalyzerEngine()
    print("Presidio loaded. Running...\n")

    latencies, fp = [], 0

    for case in attack_cases:
        text = case["user_message"]
        for t in case.get("transactions", []): text += " " + t.get("description", "")
        text += " " + case.get("llm_response", "")
        t0 = time.perf_counter()
        analyzer.analyze(text=text, language="en")
        latencies.append((time.perf_counter()-t0)*1000)

    for case in fp_cases:
        text = case["user_message"]
        for t in case.get("transactions", []): text += " " + t.get("description", "")
        t0 = time.perf_counter()
        blocked = len(analyzer.analyze(text=text, language="en")) > 0
        latencies.append((time.perf_counter()-t0)*1000)
        if blocked: fp += 1

    n_f = len(fp_cases)
    print(f"{'─'*50}")
    print(f"  Presidio Results")
    print(f"{'─'*50}")
    print(f"  FP rate    : {fp}/{n_f} ({fp/n_f*100:.1f}%)")
    print(f"  Mean lat   : {mean(latencies):.1f}ms")
    print(f"  Median lat : {median(latencies):.1f}ms")
    print(f"{'─'*50}\n")

    os.makedirs("evaluation", exist_ok=True)
    with open("evaluation/presidio_results.json", "w") as f:
        json.dump({
            "fp_rate_pct": round(fp/n_f*100, 1),
            "mean_latency_ms": round(mean(latencies), 1),
            "median_latency_ms": round(median(latencies), 1),
            "fp": fp, "n_fp": n_f,
            "note": "PII detection only — block rate not applicable as injection guard"
        }, f, indent=2)
    print("Saved → evaluation/presidio_results.json")

if __name__ == "__main__": main()   