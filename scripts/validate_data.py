#!/usr/bin/env python3
"""Validate committed ThreatWatch public data (CI gate)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tw.common import DATA_DIR, REPO_ROOT, safe_url  # noqa: E402
from tw.validate import validate_brief, validate_month, validate_relationships  # noqa: E402


def main() -> int:
    errs = []
    rel = DATA_DIR / "relationships.json"
    errs += [f"relationships: {e}" for e in validate_relationships(json.loads(rel.read_text()))]
    latest = DATA_DIR / "latest.json"
    if latest.exists():
        errs += [f"latest: {e}" for e in validate_brief(json.loads(latest.read_text()))]
    for p in sorted((DATA_DIR / "monthly").glob("????-??.json")):
        errs += [f"{p.name}: {e}" for e in validate_month(json.loads(p.read_text()))]
    cfg = json.loads((REPO_ROOT / "threatwatch" / "subscription-config.json").read_text())
    if set(cfg) - {"enabled", "signupUrl", "provider", "note"}:
        errs.append("subscription-config.json contains unexpected keys (no secrets allowed)")
    if cfg.get("enabled") and not safe_url(cfg.get("signupUrl")):
        errs.append("subscription enabled without an https signupUrl")
    for e in errs:
        print("ERROR:", e)
    print("OK" if not errs else f"{len(errs)} error(s)")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
