"""
Baseline 4: Meta PromptGuard 86M
Run in a SEPARATE terminal — loads ~300MB model.
"""
import sys
import json
import time
from pathlib import Path
from datasets import load_dataset

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

def run():
    print("Loading meta-llama/Prompt-Guard-86M...")
    from transformers import pipeline as hf_pipeline

    classifier = hf_pipeline(
        "text-classification",
        model="meta-llama/Prompt-Guard-86M",
        device=-1,
    )

    print("Loading deepset/prompt-injections test split...")
    ds = load_dataset("deepset/prompt-injections", split="test")

    TP = FP = TN = FN = 0
    latencies = []

    for row in ds:
        text   = row["text"]
        actual = row["label"]
        t0 = time.perf_counter()
        result = classifier(text[:512], truncation=True)[0]
        ms = (time.perf_counter() - t0) * 1000
        latencies.append(ms)
        blocked = result["label"] == "INJECTION"
        predicted = 1 if blocked else 0
        if predicted == 1 and actual == 1: TP += 1
        elif predicted == 1 and actual == 0: FP += 1
        elif predicted == 0 and actual == 0: TN += 1
        else: FN += 1

    total     = TP + FP + TN + FN
    precision = TP / (TP + FP) if (TP + FP) else 0
    recall    = TP / (TP + FN) if (TP + FN) else 0
    f1        = 2*precision*recall/(precision+recall) if (precision+recall) else 0
    fpr       = FP / (FP + TN) if (FP + TN) else 0
    mean_lat  = sum(latencies) / len(latencies)

    print()
    print("=" * 60)
    print("  PromptGuard 86M — deepset/prompt-injections (test)")
    print("=" * 60)
    print(f"  Total    : {total}  (injections: {TP+FN}, benign: {FP+TN})")
    print(f"  TP       : {TP}  FP: {FP}  TN: {TN}  FN: {FN}")
    print(f"  Precision: {precision*100:.1f}%")
    print(f"  Recall   : {recall*100:.1f}%")
    print(f"  F1       : {f1*100:.1f}%")
    print(f"  FPR      : {fpr*100:.1f}%")
    print(f"  Mean lat : {mean_lat:.1f}ms")
    print("=" * 60)

    out = {
        "model": "meta-llama/Prompt-Guard-86M",
        "dataset": "deepset/prompt-injections",
        "split": "test",
        "total": total,
        "TP": TP, "FP": FP, "TN": TN, "FN": FN,
        "precision_pct": round(precision*100, 2),
        "recall_pct":    round(recall*100, 2),
        "f1_pct":        round(f1*100, 2),
        "fpr_pct":       round(fpr*100, 2),
        "mean_latency_ms": round(mean_lat, 2)
    }
    with open("evaluation/promptguard_results.json", "w") as f:
        json.dump(out, f, indent=2)
    print("  Saved -> evaluation/promptguard_results.json")

if __name__ == "__main__":
    run()
