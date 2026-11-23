#!/usr/bin/env python3
"""Write a Markdown review pack of pending Global Intelligence drafts (docs/GLOBAL_INTELLIGENCE_REVIEW.md)."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REC = ROOT / "global-intelligence" / "editorial" / "records"
PENDING = {"collected", "analyzed", "verification_pending", "approved"}


def main() -> int:
    lines = ["# Global Intelligence — drafts awaiting editorial review", "",
             "Review each draft against its sources. To publish: "
             "`python scripts/approve_global.py --editor \"Your Name\" --all` (or list IDs). "
             "To change a draft, edit its JSON file in `global-intelligence/editorial/records/` first.", ""]
    n = 0
    for p in sorted(REC.glob("*.json")):
        r = json.loads(p.read_text(encoding="utf-8"))
        if r.get("publication_status") not in PENDING:
            continue
        n += 1
        lines += [f"## {r['id']} — {r['title']}", "",
                  f"**{r['priority']}** · {r['evidence_status']} · {r['primary_category']} · {', '.join(r['regions'])} · "
                  f"{', '.join(r['countries'])} · event {r['event_date']} · trend {r['trend']}", "", r["summary"], ""]
        if r.get("record_type") == "signal":
            lines += [f"- **Observed:** {r['observed_action']}", f"- **Interpretation:** {r['interpretation']}", ""]
        for key, label in (("confirmed_facts", "Confirmed facts"), ("reported_claims", "Reported claims"),
                           ("international_perspectives", "Perspectives")):
            if r.get(key):
                lines.append(f"**{label}**")
                for c in r[key]:
                    att = f" _(attributed to {c['attributed_to']})_" if c.get("attributed_to") else ""
                    lines.append(f"- {c['text']}{att} " + "".join(f"[{i + 1}]" for i in c["sources"]))
                lines.append("")
        lines += [f"**Priority rationale:** {r['priority_rationale']}", "", "**Sources**"]
        for i, s in enumerate(r["sources"], 1):
            extra = (f" — republished from {s['syndicated_from']}" if s.get("syndicated_from") else "") + \
                    (" — state-affiliated" if s.get("state_affiliated") else "")
            lines.append(f"{i}. {s['publisher']}, \"{s['title']}\" ({s['published']}) {s['url']}{extra}")
        lines += ["", "---", ""]
    out = ROOT / "docs" / "GLOBAL_INTELLIGENCE_REVIEW.md"
    out.write_text("\n".join(lines) + f"\n{n} draft(s).\n", encoding="utf-8")
    print(f"Wrote {out.relative_to(ROOT)} ({n} drafts)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
