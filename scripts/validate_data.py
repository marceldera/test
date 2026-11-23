#!/usr/bin/env python3
"""Validate committed ThreatWatch public data (CI gate)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tw.common import DATA_DIR, REPO_ROOT, safe_url  # noqa: E402
from tw.validate import validate_brief, validate_month, validate_relationships  # noqa: E402
from tw.catalog import validate_record  # noqa: E402
from tw.detections import load_reviews  # noqa: E402
from tw.playbooks import load_playbooks, load_products  # noqa: E402


def main() -> int:
    errs = []
    rel = DATA_DIR / "relationships.json"
    errs += [f"relationships: {e}" for e in validate_relationships(json.loads(rel.read_text()))]
    latest = DATA_DIR / "latest.json"
    if latest.exists():
        lb = json.loads(latest.read_text())
        errs += [f"latest: {e}" for e in validate_brief(lb)]
        if "report" in lb:
            from tw.report import validate_report
            errs += [f"latest report: {e}" for e in validate_report(lb["report"])]
    from tw.report import M_SECTION_IDS, validate_report as _vr
    for p in sorted((DATA_DIR / "monthly").glob("20*.json")):
        md = json.loads(p.read_text())
        if "report" in md:
            errs += [f"monthly/{p.name} report: {e}" for e in _vr(md["report"], M_SECTION_IDS)]
    from tw.brief import safe_editorial
    for p in sorted((DATA_DIR / "editorial").glob("*.json")):
        try:
            if p.name.startswith("monthly-"):
                from tw.report import safe_report_editorial
                safe_report_editorial(json.loads(p.read_text()).get("report"), M_SECTION_IDS)
                continue
            safe_editorial(json.loads(p.read_text()))
        except (ValueError, TypeError, AttributeError) as exc:
            errs.append(f"editorial/{p.name}: {exc}")
    for p in sorted((DATA_DIR / "monthly").glob("????-??.json")):
        errs += [f"{p.name}: {e}" for e in validate_month(json.loads(p.read_text()))]
    idx = DATA_DIR / "cves" / "index.json"
    if idx.exists():
        index = json.loads(idx.read_text())
        ids = {row[0] for row in index["items"]}
        files = {p.stem: p for p in (DATA_DIR / "cves").glob("[0-9][0-9][0-9][0-9]/CVE-*.json")}
        if ids != set(files):
            errs.append(f"cves: index has {len(ids)} ids but {len(files)} record files")
        for p in files.values():
            errs += [f"cves: {e}" for e in validate_record(json.loads(p.read_text()))]
    try:
        load_reviews(json.loads((DATA_DIR / "validation" / "reviews.json").read_text()))
    except (ValueError, FileNotFoundError) as exc:
        errs.append(f"reviews.json: {exc}")
    for name, loader, key in (("products.json", load_products, "products"), ("playbooks.json", load_playbooks, "playbooks")):
        try:
            loader(json.loads((DATA_DIR / "validation" / name).read_text()))
        except (ValueError, FileNotFoundError) as exc:
            errs.append(f"{name}: {exc}")
    cfg = json.loads((REPO_ROOT / "threatwatch" / "subscription-config.json").read_text())
    if set(cfg) - {"enabled", "signupUrl", "provider", "note"}:
        errs.append("subscription-config.json contains unexpected keys (no secrets allowed)")
    if cfg.get("enabled") and not safe_url(cfg.get("signupUrl")):
        errs.append("subscription enabled without an https signupUrl")
    if safe_url(cfg.get("signupUrl")):
        from urllib.parse import urlsplit
        host = urlsplit(cfg["signupUrl"]).netloc
        for page in sorted((REPO_ROOT / "threatwatch").glob("*.html")):
            txt = page.read_text()
            if 'id="subscribe-form"' in txt and f"form-action https://{host}" not in txt:
                errs.append(f"{page.name}: CSP form-action does not allow the signup host {host}")
    from tw.global_intel import build as build_global
    errs += [f"global-intelligence: {e}" for e in build_global(REPO_ROOT, write=False)[1]]
    for e in errs:
        print("ERROR:", e)
    print("OK" if not errs else f"{len(errs)} error(s)")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
