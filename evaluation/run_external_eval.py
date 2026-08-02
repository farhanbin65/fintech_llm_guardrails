"""
External evaluation: run Layer 1 sanitiser against deepset/prompt-injections test set.
Reports precision, recall, F1, FPR vs our hand-crafted corpus results.
"""

import sys
import json
import time
from pathlib import Path
from datasets import load_dataset

sys.path.insert(0, str(Path(__file__).parent.parent))
from fintech_llm_guard.sanitiser import InputSanitiser

def run():
    print("Loading deepset/prompt-injections test split...")
    ds = load_dataset("deepset/prompt-injections", split="test")

    sanitiser = InputSanitiser()

    TP = FP = TN = FN = 0
    results = []
    latencies = []

    for row in ds:
        text   = row["text"]
        actual = row["label"]   # 1 = injection, 0 = benign

        t0 = time.perf_counter()
        result = sanitiser.check(text)
        ms = (time.perf_counter() - t0) * 1000
        latencies.append(ms)

        predicted = 1 if result.is_suspicious else 0

        if predicted == 1 and actual == 1: TP += 1
        elif predicted == 1 and actual == 0: FP += 1
        elif predicted == 0 and actual == 0: TN += 1
        else:                                FN += 1

        results.append({
            "text":      text[:80],
            "actual":    actual,
            "predicted": predicted,
            "blocked":   result.is_suspicious,
            "latency_ms": round(ms, 2)
        })

    total     = TP + FP + TN + FN
    precision = TP / (TP + FP) if (TP + FP) else 0
    recall    = TP / (TP + FN) if (TP + FN) else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    fpr       = FP / (FP + TN) if (FP + TN) else 0
    accuracy  = (TP + TN) / total
    mean_lat  = sum(latencies) / len(latencies)

    print()
    print("=" * 60)
    print("  External Evaluation — deepset/prompt-injections (test)")
    print("=" * 60)
    print(f"  Total cases   : {total}  (injections: {TP+FN}, benign: {FP+TN})")
    print(f"  TP            : {TP}")
    print(f"  FP            : {FP}")
    print(f"  TN            : {TN}")
    print(f"  FN            : {FN}")
    print("-" * 60)
    print(f"  Accuracy      : {accuracy*100:.1f}%")
    print(f"  Precision     : {precision*100:.1f}%")
    print(f"  Recall        : {recall*100:.1f}%")
    print(f"  F1 Score      : {f1*100:.1f}%")
    print(f"  FPR           : {fpr*100:.1f}%  (false alarm rate)")
    print(f"  Mean latency  : {mean_lat:.2f}ms")
    print("=" * 60)

    fn_cases = [r for r in results if r["actual"] == 1 and r["predicted"] == 0]
    if fn_cases:
        print(f"\n  Missed injections (FN = {len(fn_cases)}):")
        for r in fn_cases[:8]:
            print(f"    - {r['text']!r}")
        if len(fn_cases) > 8:
            print(f"    ... and {len(fn_cases)-8} more")

    fp_cases = [r for r in results if r["actual"] == 0 and r["predicted"] == 1]
    if fp_cases:
        print(f"\n  False alarms (FP = {len(fp_cases)}):")
        for r in fp_cases[:5]:
            print(f"    - {r['text']!r}")

    out = {
        "dataset": "deepset/prompt-injections",
        "split": "test",
        "total": total,
        "TP": TP, "FP": FP, "TN": TN, "FN": FN,
        "accuracy_pct":  round(accuracy  * 100, 2),
        "precision_pct": round(precision * 100, 2),
        "recall_pct":    round(recall    * 100, 2),
        "f1_pct":        round(f1        * 100, 2),
        "fpr_pct":       round(fpr       * 100, 2),
        "mean_latency_ms": round(mean_lat, 2)
    }

    Path("evaluation").mkdir(exist_ok=True)
    with open("evaluation/external_eval_results.json", "w") as f:
        json.dump(out, f, indent=2)
    print("\n  Saved → evaluation/external_eval_results.json")

if __name__ == "__main__":
    run()