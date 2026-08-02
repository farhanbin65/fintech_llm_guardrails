"""
Fix mislabeled V2/V3 corpus cases.

Ten cases across vector2_transaction.json and vector3_csv.json contain genuine
prompt-injection payloads in their transaction description field but were
uniformly labeled expected_blocked=False (the files were authored as
benign-only sets). This script flips expected_blocked=True for the ten
confirmed attack cases, identified by manual review of the injected content
and cross-checked against evaluation/redteam_results.json.

Run from repo root:
    python3 fix_v2v3_labels.py
"""
import json
from pathlib import Path

# Confirmed via manual review — each of these descriptions contains an
# unambiguous injection payload. Split into two groups:
#
#  CAUGHT  — system correctly blocked these; label was simply wrong.
#  MISSED  — system did NOT block these (actual_blocked=False, verified against
#            evaluation/redteam_results.json). Root cause: the provenance
#            scanner's regex vocabulary is narrower than the direct-injection
#            scanner's — these evade by substituting "rules" for "instructions",
#            using hyphens/punctuation instead of spaces, splitting the payload
#            across a staged/fragmented description ("Part 1: Ignore"), or using
#            exfiltration verbs ("output", "reveal all") outside the matched
#            verb list (send|forward|email|exfiltrate). This is a genuine
#            detection gap, not a labeling artifact — report it in §6.2
#            alongside V4/V5 as a third analysed limitation.
ATTACK_IDS = {
    "vector2_transaction.json": {
        "caught": ["V2-001", "V2-002", "V2-004"],
        "missed": ["V2-009", "V2-010", "V2-011"],
    },
    "vector3_csv.json": {
        "caught": ["V3-001", "V3-009", "V3-010"],
        "missed": ["V3-003"],
    },
}

ATTACKS_DIR = Path("tests/attacks")

def main():
    for fname, groups in ATTACK_IDS.items():
        path = ATTACKS_DIR / fname
        data = json.loads(path.read_text())
        cases = data if isinstance(data, list) else data.get("cases", data)

        all_ids = set(groups["caught"]) | set(groups["missed"])
        flipped = []
        for c in cases:
            cid = c.get("id") or c.get("case_id")
            if cid in all_ids and c.get("expected_blocked") is False:
                c["expected_blocked"] = True
                tag = "caught" if cid in groups["caught"] else "missed (detection gap)"
                flipped.append((cid, tag))

        path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        print(f"{fname}: flipped {len(flipped)}")
        for cid, tag in flipped:
            print(f"  {cid} -> {tag}")
        missing = all_ids - {cid for cid, _ in flipped}
        if missing:
            print(f"  WARNING: expected to flip {missing} but not found / already True.")

if __name__ == "__main__":
    main()