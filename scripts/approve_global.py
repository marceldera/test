#!/usr/bin/env python3
"""Approve and publish Global Intelligence drafts after editorial review.

    python scripts/approve_global.py --editor "Marcel Dera" --all          # every pending draft
    python scripts/approve_global.py --editor "Marcel Dera" GI-2026-0001 GI-2026-0004
    python scripts/approve_global.py --list                                  # show pending drafts

For each selected draft this records the editor and time as the approval, sets the publication time,
starts the public update history, marks it published, then rebuilds the public data. If the build
fails, every record is restored and nothing is published.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from tw.global_intel import build  # noqa: E402

REC = ROOT / "global-intelligence" / "editorial" / "records"
PENDING = {"collected", "analyzed", "verification_pending", "approved"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ids", nargs="*")
    ap.add_argument("--editor")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    drafts = {}
    for p in sorted(REC.glob("*.json")):
        r = json.loads(p.read_text(encoding="utf-8"))
        if r.get("publication_status") in PENDING:
            drafts[r["id"]] = (p, r)
    if a.list or not (a.all or a.ids):
        for rid, (_, r) in drafts.items():
            print(f"{rid}  {r['priority']:<8} {r['evidence_status']:<22} {r['title']}")
        print(f"{len(drafts)} pending draft(s).")
        return 0
    if not a.editor or len(a.editor.strip()) < 3:
        print("--editor is required (the name recorded as the approving editor).", file=sys.stderr)
        return 2
    chosen = list(drafts) if a.all else a.ids
    missing = [i for i in chosen if i not in drafts]
    if missing:
        print(f"Not pending drafts: {missing}", file=sys.stderr)
        return 2
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    backup = {rid: drafts[rid][0].read_text(encoding="utf-8") for rid in chosen}
    for rid in chosen:
        p, r = drafts[rid]
        r.update(publication_status="published", approved_by=a.editor.strip(), approved_at=now,
                 published_at=now, last_verified=now, last_substantive_update=now,
                 update_history=[{"date": now, "type": "published",
                                  "summary": f"Published after editorial review by {a.editor.strip()}."}])
        p.write_text(json.dumps(r, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    out, errs = build(ROOT)
    if errs:
        for rid, text in backup.items():
            drafts[rid][0].write_text(text, encoding="utf-8")
        print("APPROVAL ROLLED BACK — nothing published:", file=sys.stderr)
        for e in errs:
            print("  -", e, file=sys.stderr)
        return 1
    c = out["executive-summary.json"]["counts"]
    print(f"Published {len(chosen)} record(s) approved by {a.editor.strip()}. "
          f"Live: {c['active']} active events, {c['signals']} signals. Commit and push to publish.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
