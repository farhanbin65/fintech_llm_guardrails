"""Fintech LLM Guard isolated baseline — reuses single pipeline to avoid OOM."""
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

    true_attacks = [c for c in attack_cases if c["expected_blocked"]]
    print(f"Fintech LLM Guard — {len(true_attacks)} attack cases, {len(fp_cases)} legit queries\n")

    from middleware.sanitiser import InputSanitiser
    from middleware.separator import StructuralSeparator
    from middleware.redactor import PIIRedactor
    from middleware.output_validator import OutputValidator

    # Instantiate each layer once — reuse across all cases
    sanitiser = InputSanitiser()
    separator = StructuralSeparator()
    redactor = PIIRedactor()
    validator = OutputValidator()

    DEFAULT_SAFE = "You spent £120 on groceries last month."
    tp, fp, latencies = 0, 0, []

    def run_case(user_message, transactions, llm_response):
        t0 = time.perf_counter()

        # L1
        san = sanitiser.check(user_message)
        if san.is_suspicious:
            return True, (time.perf_counter()-t0)*1000

        # L2
        sep = separator.build_messages(
            user_message=user_message,
            transactions=transactions,
        )

        # L3 — redact user message
        red = redactor.redact(user_message)
        mapping = red.mapping

        # L4 — validate LLM response
        val = validator.validate(llm_response, pii_mapping=mapping)
        blocked = not val.is_safe
        return blocked, (time.perf_counter()-t0)*1000

    print("Warming up spaCy model...")
    redactor.redact("warm up John Smith 12345678")
    print("Ready.\n")

    for case in attack_cases:
        blocked, lat = run_case(
            case["user_message"],
            case.get("transactions", []),
            case.get("llm_response", DEFAULT_SAFE),
        )
        latencies.append(lat)
        if case["expected_blocked"] and blocked:
            tp += 1

    for case in fp_cases:
        blocked, lat = run_case(
            case["user_message"],
            case.get("transactions", []),
            DEFAULT_SAFE,
        )
        latencies.append(lat)
        if blocked:
            fp += 1

    n_a, n_f = len(true_attacks), len(fp_cases)
    print(f"  Block rate : {tp}/{n_a} ({tp/n_a*100:.1f}%)")
    print(f"  FP rate    : {fp}/{n_f} ({fp/n_f*100:.1f}%)")
    print(f"  Mean lat   : {mean(latencies):.1f}ms")
    print(f"  Median lat : {median(latencies):.1f}ms")

    os.makedirs("evaluation", exist_ok=True)
    with open("evaluation/ours_results.json", "w") as f:
        json.dump({
            "block_rate_pct": round(tp/n_a*100, 1),
            "fp_rate_pct": round(fp/n_f*100, 1),
            "mean_latency_ms": round(mean(latencies), 1),
            "median_latency_ms": round(median(latencies), 1),
            "tp": tp, "fp": fp, "n_attacks": n_a, "n_fp": n_f,
        }, f, indent=2)
    print("Saved → evaluation/ours_results.json")

if __name__ == "__main__": main()