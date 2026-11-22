#!/usr/bin/env python3
"""Aegis ThreatWatch publisher.

fetch → validate schema → normalize → dedupe → enrich → prioritize → compose
→ quality gate → publish versioned JSON. On any failure the last good edition
is left untouched and the process exits non-zero.

Usage:
  python scripts/build_brief.py            # scheduled mode (ET time gate + idempotency)
  python scripts/build_brief.py --force    # publish regardless of gate
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tw.brief import build_daily, build_month, recent_months, safe_editorial  # noqa: E402
from tw.common import DATA_DIR, ET, SourceError, iso, now_utc, read_json, write_json  # noqa: E402
from tw.sources import collect_epss, collect_kev, collect_nvd  # noqa: E402
from tw.validate import validate_brief, validate_month  # noqa: E402
from tw.report import (Catalog, M_SECTION_IDS, compose, compose_month, safe_report_editorial,  # noqa: E402
                       validate_report)

EARLIEST_ET = (6, 45)   # don't publish before 06:45 ET (target: brief live by 07:00 ET)
REPORT_STATE = "report-state.json"
RETENTION_DAYS = int(os.environ.get("TW_RETENTION_DAYS", "365"))


def gh_output(**kv) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            for k, v in kv.items():
                fh.write(f"{k}={v}\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="ignore time gate and idempotency")
    ap.add_argument("--refresh-report", action="store_true",
                    help="re-compose the latest edition's report (after editing its editorial file); "
                         "does not re-run the KEV diff")
    args = ap.parse_args()
    if args.refresh_report:
        return refresh_report()

    now = now_utc()
    now_et = now.astimezone(ET)
    edition = now_et.date().isoformat()
    latest = read_json(DATA_DIR / "latest.json", {}) or {}
    status_path = DATA_DIR / "status.json"
    status = read_json(status_path, {}) or {}

    if not args.force:
        if (now_et.hour, now_et.minute) < EARLIEST_ET:
            print(f"Gate: {now_et:%H:%M} ET is before publication time; skipping.")
            gh_output(published="false")
            return 0
        if latest.get("edition") == edition:
            print(f"Gate: edition {edition} already published; skipping.")
            gh_output(published="false")
            return 0

    status["lastAttemptAt"] = iso(now)
    try:
        kev = collect_kev()
        by_date = sorted(kev["records"], key=lambda r: r["dateAdded"], reverse=True)
        months = recent_months(now, 6)
        month_cves = [r["cve"] for r in kev["records"] if r["dateAdded"][:7] in months]
        epss = collect_epss(month_cves)
        state = read_json(DATA_DIR / "state.json", {}) or {}
        prev = set(state.get("kevIds") or [])
        cutoff = (now_et.date() - timedelta(days=1)).isoformat()
        if prev:
            new_ids = [r["cve"] for r in by_date if r["cve"] not in prev]
        else:
            new_ids = [r["cve"] for r in by_date if r["dateAdded"] >= cutoff]
        nvd = collect_nvd(new_ids)

        editorial = None
        ed_path = DATA_DIR / "editorial" / f"{edition}.json"
        if ed_path.exists():
            editorial = safe_editorial(read_json(ed_path))

        brief, new_state = build_daily(kev, epss, nvd, state, editorial, now)
        report_state = attach_report(brief, editorial, now)
        errs = validate_brief(brief) + validate_report(brief["report"])
        monthlies = {m: build_month(kev, epss, m, now) for m in months}
        for m, doc in monthlies.items():
            errs += [f"{m}: {e}" for e in validate_month(doc)]
        attach_month_reports(monthlies, now)
        for m, doc in monthlies.items():
            errs += [f"{m} report: {e}" for e in validate_report(doc["report"], M_SECTION_IDS)]
        if errs:
            raise SourceError("Quality gate failed:\n  - " + "\n  - ".join(errs))
    except (SourceError, ValueError) as exc:
        status.update({"ok": False, "lastError": str(exc)[:2000]})
        write_json(status_path, status)
        print(f"PUBLISH BLOCKED: {exc}", file=sys.stderr)
        gh_output(published="false")
        return 1

    # ---- publish (only after every gate passed)
    write_json(DATA_DIR / "briefs" / f"{edition}.json", brief)
    for m, doc in monthlies.items():
        write_json(DATA_DIR / "monthly" / f"{m}.json", doc)
    write_json(DATA_DIR / "monthly" / "index.json",
               {"months": [{"month": m, "kevAdded": monthlies[m]["metrics"][0]["value"],
                            "complete": monthlies[m]["complete"]} for m in months]})
    _prune_and_index(now)
    write_json(DATA_DIR / "latest.json", brief)
    write_json(DATA_DIR / "state.json", new_state)
    write_json(DATA_DIR / REPORT_STATE, report_state)
    status.update({"ok": True, "lastError": None, "lastSuccessAt": iso(now), "lastEdition": edition,
                   "kevCatalogVersion": kev.get("catalogVersion"), "kevRejectedRecords": kev["rejected"]})
    write_json(status_path, status)
    print(f"Published edition {edition}: {brief['executive']['counts']}")
    gh_output(published="true", edition=edition)
    # Vulnerability Validation catalog: built right after each published edition, so the
    # existing workflow needs no extra step. Set TW_SKIP_CATALOG=1 to disable.
    if os.environ.get("TW_SKIP_CATALOG") != "1":
        import build_catalog
        print("Building Vulnerability Validation catalog…")
        if build_catalog.main() != 0:
            print("Catalog build failed — see threatwatch/data/cves/status.json. "
                  "The brief was published; the last good catalog stays live.", file=sys.stderr)
            return 1
        # the catalog now holds today's zero-day / PoC / ATT&CK data: re-compose the report with it
        return refresh_report()
    return 0


def attach_report(brief: dict, editorial: dict | None, now) -> dict:
    """Compose the seven-section report into brief['report']; returns the new tracking state."""
    track = read_json(DATA_DIR / REPORT_STATE, {}) or {}
    report, new_track = compose(brief, Catalog(DATA_DIR), track, editorial, now)
    brief["report"] = report
    return new_track


def month_editorial(month: str) -> dict | None:
    p = DATA_DIR / "editorial" / f"monthly-{month}.json"
    if not p.exists():
        return None
    raw = read_json(p) or {}
    return {"reviewedBy": raw.get("reviewedBy"),
            "report": safe_report_editorial(raw.get("report"), M_SECTION_IDS)}


def attach_month_reports(monthlies: dict, now) -> None:
    cat = Catalog(DATA_DIR)
    for m, doc in monthlies.items():
        doc["report"] = compose_month(doc, cat, month_editorial(m), now)


BACKFILL_DAYS = 7


def backfill_reports(latest_edition: str, now) -> list[str]:
    """Give the last 7 editions the document format if they were published before it existed."""
    done = []
    idx = read_json(DATA_DIR / "briefs" / "index.json", {}) or {}
    cat = Catalog(DATA_DIR)
    for e in [x["edition"] for x in idx.get("editions") or []][:BACKFILL_DAYS]:
        if e == latest_edition:
            continue
        path = DATA_DIR / "briefs" / f"{e}.json"
        b = read_json(path)
        if not b or b.get("report"):
            continue
        ed_path = DATA_DIR / "editorial" / f"{e}.json"
        editorial = safe_editorial(read_json(ed_path)) if ed_path.exists() else None
        rep, _ = compose(b, cat, {}, editorial, now)  # throwaway tracking state
        if not any(s["source"] == "editorial" for s in rep["sections"]):
            rep["prepared"] = "Automated edition (reconstructed from catalog data)"
        if not validate_report(rep):
            b["report"] = rep
            write_json(path, b)
            done.append(e)
    return done


def refresh_report() -> int:
    """Re-compose the latest edition's report from the current catalog and editorial file."""
    latest = read_json(DATA_DIR / "latest.json", {}) or {}
    edition = latest.get("edition")
    if not edition:
        print("No published edition to refresh.", file=sys.stderr)
        return 1
    try:
        editorial = None
        ed_path = DATA_DIR / "editorial" / f"{edition}.json"
        if ed_path.exists():
            editorial = safe_editorial(read_json(ed_path))
        report_state = attach_report(latest, editorial, now_utc())
        errs = validate_report(latest["report"])
        if errs:
            raise ValueError("Report quality gate failed:\n  - " + "\n  - ".join(errs))
    except (ValueError, KeyError) as exc:
        print(f"REPORT REFRESH BLOCKED (published edition unchanged): {exc}", file=sys.stderr)
        return 1
    write_json(DATA_DIR / "briefs" / f"{edition}.json", latest)
    write_json(DATA_DIR / "latest.json", latest)
    write_json(DATA_DIR / REPORT_STATE, report_state)
    now = now_utc()
    try:
        filled = backfill_reports(edition, now)
        months = {}
        for row in (read_json(DATA_DIR / "monthly" / "index.json", {}) or {}).get("months") or []:
            doc = read_json(DATA_DIR / "monthly" / f"{row['month']}.json")
            if doc:
                months[row["month"]] = doc
        attach_month_reports(months, now)
        for m, doc in months.items():
            errs = validate_report(doc["report"], M_SECTION_IDS)
            if errs:
                raise ValueError(f"{m} report: " + "; ".join(errs))
        for m, doc in months.items():
            write_json(DATA_DIR / "monthly" / f"{m}.json", doc)
    except (ValueError, KeyError) as exc:
        print(f"Monthly/backfill composition skipped: {exc}", file=sys.stderr)
        return 1
    print(f"Backfilled daily reports: {filled}; monthly summaries composed: {sorted(months)}")
    print(f"Report for {edition} composed: {len(latest['report']['prioritized'])} prioritized CVEs; "
          f"editorial sections: {[s['id'] for s in latest['report']['sections'] if s['source'] == 'editorial']}")
    return 0


def _prune_and_index(now) -> None:
    bdir = DATA_DIR / "briefs"
    keep_after = (now.astimezone(ET).date() - timedelta(days=RETENTION_DAYS)).isoformat()
    editions = []
    for p in sorted(bdir.glob("????-??-??.json"), reverse=True):
        if p.stem < keep_after:
            p.unlink()
            continue
        b = read_json(p, {})
        editions.append({"edition": p.stem, "kevAdded": b.get("executive", {}).get("counts", {}).get("kevAdded"),
                         "emergency": b.get("executive", {}).get("counts", {}).get("emergency")})
    write_json(bdir / "index.json", {"editions": editions})


if __name__ == "__main__":
    sys.exit(main())
