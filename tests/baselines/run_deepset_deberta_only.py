"""
Baseline 3: Meta PromptGuard 86M
Runs against our internal 107-case corpus AND deepset external test set.
Run in a SEPARATE terminal — loads ~86MB model.
"""
import sys
import json
import time
from pathlib import Path
from datasets import load_dataset

def run():
    print("Loading deepset/deberta-v3-base-injection...")
    from transformers import pipeline as hf_pipeline

    classifier = hf_pipeline(
        "text-classification",
        model="deepset/deberta-v3-base-injection",
        device=-1,  # CPU
    )

    def is_injection(text: str) -> tuple[bool, float]:
        result = classifier(text[:512], truncation=True)[0]
        # PromptGuard labels: INJECTION or BENIGN
        blocked = result["label"] in ("INJECTION", "LABEL_1")
        return blocked, result["score"]

    # ── Internal corpus ───────────────────────────────────────────────────────
    print("\nLoading internal corpus...")
    corpus_path = Path("evaluation/corpus.json")
    if corpus_path.exists():
        with open(corpus_path) as f:
            corpus = json.load(f)
        int_tp = int_fp = int_tn = int_fn = 0
        int_lats = []
        for case in corpus:
            text     = case.get("input", case.get("text", ""))
            expected = case.get("expected_blocked", case.get("label", 1))
            t0 = time.perf_counter()
            blocked, _ = is_injection(text)
            ms = (time.perf_counter() - t0) * 1000
            int_lats.append(ms)
            predicted = 1 if blocked else 0
            if predicted == 1 and expected == 1: int_tp += 1
            elif predicted == 1 and expected == 0: int_fp += 1
            elif predicted == 0 and expected == 0: int_tn += 1
            else: int_fn += 1
        int_total = int_tp + int_fp + int_tn + int_fn
        int_prec  = int_tp / (int_tp + int_fp) if (int_tp + int_fp) else 0
        int_rec   = int_tp / (int_tp + int_fn) if (int_tp + int_fn) else 0
        int_f1    = 2*int_prec*int_rec/(int_prec+int_rec) if (int_prec+int_rec) else 0
        int_fpr   = int_fp / (int_fp + int_tn) if (int_fp + int_tn) else 0
        int_mean  = sum(int_lats) / len(int_lats)
        print(f"\n  Internal corpus ({int_total} cases)")
        print(f"  Block rate : {int_tp}/{int_tp+int_fn} ({(int_tp/(int_tp+int_fn))*100:.1f}%)")
        print(f"  FPR        : {int_fp}/{int_fp+int_tn} ({int_fpr*100:.1f}%)")
        print(f"  Precision  : {int_prec*100:.1f}%")
        print(f"  Recall     : {int_rec*100:.1f}%")
        print(f"  F1         : {int_f1*100:.1f}%")
        print(f"  Mean lat   : {int_mean:.1f}ms")
    else:
        print("  No internal corpus found — skipping.")
        int_tp = int_fp = int_tn = int_fn = 0
        int_mean = 0

    # ── External corpus (deepset) ─────────────────────────────────────────────
    print("\nLoading deepset/prompt-injections test split...")
    ds = load_dataset("deepset/prompt-injections", split="test")

    ext_tp = ext_fp = ext_tn = ext_fn = 0
    ext_lats = []

    for row in ds:
        text   = row["text"]
        actual = row["label"]
        t0 = time.perf_counter()
        blocked, _ = is_injection(text)
        ms = (time.perf_counter() - t0) * 1000
        ext_lats.append(ms)
        predicted = 1 if blocked else 0
        if predicted == 1 and actual == 1: ext_tp += 1
        elif predicted == 1 and actual == 0: ext_fp += 1
        elif predicted == 0 and actual == 0: ext_tn += 1
        else: ext_fn += 1

    ext_total = ext_tp + ext_fp + ext_tn + ext_fn
    ext_prec  = ext_tp / (ext_tp + ext_fp) if (ext_tp + ext_fp) else 0
    ext_rec   = ext_tp / (ext_tp + ext_fn) if (ext_tp + ext_fn) else 0
    ext_f1    = 2*ext_prec*ext_rec/(ext_prec+ext_rec) if (ext_prec+ext_rec) else 0
    ext_fpr   = ext_fp / (ext_fp + ext_tn) if (ext_fp + ext_tn) else 0
    ext_mean  = sum(ext_lats) / len(ext_lats)

    print(f"\n  External corpus — deepset ({ext_total} cases)")
    print(f"  Block rate : {ext_tp}/{ext_tp+ext_fn} ({(ext_tp/(ext_tp+ext_fn))*100:.1f}%)")
    print(f"  FPR        : {ext_fp}/{ext_fp+ext_tn} ({ext_fpr*100:.1f}%)")
    print(f"  Precision  : {ext_prec*100:.1f}%")
    print(f"  Recall     : {ext_rec*100:.1f}%")
    print(f"  F1         : {ext_f1*100:.1f}%")
    print(f"  Mean lat   : {ext_mean:.1f}ms")

    out = {
        "model": "deepset/deberta-v3-base-injection",
        "external": {
            "dataset": "deepset/prompt-injections",
            "total": ext_total,
            "TP": ext_tp, "FP": ext_fp, "TN": ext_tn, "FN": ext_fn,
            "precision_pct": round(ext_prec*100, 2),
            "recall_pct":    round(ext_rec*100, 2),
            "f1_pct":        round(ext_f1*100, 2),
            "fpr_pct":       round(ext_fpr*100, 2),
            "mean_latency_ms": round(ext_mean, 2),
        }
    }
    Path("evaluation").mkdir(exist_ok=True)
    with open("evaluation/promptguard_results.json", "w") as f:
        json.dump(out, f, indent=2)
    print("\n  Saved → evaluation/promptguard_results.json")

if __name__ == "__main__":
    run()
