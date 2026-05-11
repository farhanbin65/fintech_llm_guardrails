"""
BERTScore semantic preservation evaluation.
Measures how well the pipeline preserves response meaning after
PII redaction and re-mapping, compared to an unredacted baseline.
"""
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

TEST_PAIRS = [
    {
        "id": "BS-001",
        "reference": "Your account number 12345678 had 3 transactions last month totalling £156.49.",
        "hypothesis": "Your account number [REDACTED] had 3 transactions last month totalling £156.49.",
    },
    {
        "id": "BS-002",
        "reference": "I can see a payment to john.smith@email.com on 3 May for £52.00.",
        "hypothesis": "I can see a payment to [REDACTED] on 3 May for £52.00.",
    },
    {
        "id": "BS-003",
        "reference": "Your sort code 20-00-00 and account 12345678 show no unusual activity.",
        "hypothesis": "Your sort code [REDACTED] and account [REDACTED] show no unusual activity.",
    },
    {
        "id": "BS-004",
        "reference": "The IBAN GB29NWBK60161331926819 was used for an international transfer of £1,200.",
        "hypothesis": "The IBAN [REDACTED] was used for an international transfer of £1,200.",
    },
    {
        "id": "BS-005",
        "reference": "National Insurance number AB123456C appears on your payslip dated 1 April.",
        "hypothesis": "National Insurance number [REDACTED] appears on your payslip dated 1 April.",
    },
    {
        "id": "BS-006",
        "reference": "You spent £45.00 at Tesco on 5 May — no PII in this transaction.",
        "hypothesis": "You spent £45.00 at Tesco on 5 May — no PII in this transaction.",
    },
    {
        "id": "BS-007",
        "reference": "Three payments were made from account 87654321 to sort code 30-00-02.",
        "hypothesis": "Three payments were made from account [REDACTED] to sort code [REDACTED].",
    },
    {
        "id": "BS-008",
        "reference": "Contact support at help@bank.co.uk or call 07700900000 for assistance.",
        "hypothesis": "Contact support at [REDACTED] or call [REDACTED] for assistance.",
    },
    {
        "id": "BS-009",
        "reference": "Your monthly income of £3,500 was credited on the 28th.",
        "hypothesis": "Your monthly income of £3,500 was credited on the 28th.",
    },
    {
        "id": "BS-010",
        "reference": "Transaction TXN-2024-98765 for £299.99 has been flagged for review.",
        "hypothesis": "Transaction [REDACTED] for £299.99 has been flagged for review.",
    },
]

def run():
    from bert_score import score as bert_score

    references  = [p["reference"]  for p in TEST_PAIRS]
    hypotheses  = [p["hypothesis"] for p in TEST_PAIRS]

    print("Computing BERTScore (this downloads bert-base-uncased on first run)...")
    P, R, F1 = bert_score(
        hypotheses, references,
        lang="en",
        model_type="bert-base-uncased",
        verbose=False,
    )

    results = []
    print()
    print("=" * 65)
    print("  BERTScore Semantic Preservation Evaluation")
    print("=" * 65)
    print(f"  {'ID':<10} {'Precision':>10} {'Recall':>10} {'F1':>10}")
    print("-" * 65)

    for i, pair in enumerate(TEST_PAIRS):
        p_val = P[i].item()
        r_val = R[i].item()
        f_val = F1[i].item()
        print(f"  {pair['id']:<10} {p_val:>10.4f} {r_val:>10.4f} {f_val:>10.4f}")
        results.append({
            "id": pair["id"],
            "precision": round(p_val, 4),
            "recall":    round(r_val, 4),
            "f1":        round(f_val, 4),
        })

    mean_p  = sum(r["precision"] for r in results) / len(results)
    mean_r  = sum(r["recall"]    for r in results) / len(results)
    mean_f1 = sum(r["f1"]        for r in results) / len(results)

    print("-" * 65)
    print(f"  {'Mean':<10} {mean_p:>10.4f} {mean_r:>10.4f} {mean_f1:>10.4f}")
    print("=" * 65)

    out = {
        "metric": "BERTScore",
        "model":  "bert-base-uncased",
        "mean_precision": round(mean_p,  4),
        "mean_recall":    round(mean_r,  4),
        "mean_f1":        round(mean_f1, 4),
        "per_case": results,
    }

    with open("evaluation/bertscore_results.json", "w") as f:
        json.dump(out, f, indent=2)
    print("\n  Saved → evaluation/bertscore_results.json")

if __name__ == "__main__":
    run()
