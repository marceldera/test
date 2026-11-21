#!/usr/bin/env python3
"""Build the Vulnerability Validation CVE catalog (Phase 1, public, read-only).

Writes under threatwatch/data/:
  cves/index.json            compact search index
  cves/<year>/<CVE>.json     one record per CVE (rewritten only when it changes)
  cves/epss.json             EPSS scores (single file; changes daily)
  cves/status.json           last attempt / success, coverage, warnings
  cves/state.json            NVD sync cursor
  validation/nuclei-index.json  cached template index
  validation/reviews.json       Aegis-curated reviews (hand-edited)

Env: NVD_API_KEY (optional), TW_NUCLEI_DIR + TW_NUCLEI_COMMIT (optional checkout),
     TW_NVD_BACKFILL_DAYS (30), TW_RETAIN_DAYS (120), TW_NVD_LOOKUPS (auto).
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tw import catalog as C  # noqa: E402
from tw.common import DATA_DIR, SourceError, fetch_json, iso, now_utc, read_json, write_json  # noqa: E402
from tw.detections import index_nuclei, load_reviews, merge  # noqa: E402
from tw.sources import NVD_URL, collect_epss, collect_kev  # noqa: E402

CVE_DIR = DATA_DIR / "cves"
VAL_DIR = DATA_DIR / "validation"
BACKFILL_DAYS = int(os.environ.get("TW_NVD_BACKFILL_DAYS", "30"))
RETAIN_DAYS = int(os.environ.get("TW_RETAIN_DAYS", "120"))


def main() -> int:
    now = now_utc()
    status = read_json(CVE_DIR / "status.json", {}) or {}
    status["lastAttemptAt"] = iso(now)
    warnings: list[str] = []
    try:
        result = build(now, warnings)
    except (SourceError, ValueError) as exc:
        status.update({"ok": False, "lastError": str(exc)[:2000]})
        write_json(CVE_DIR / "status.json", status)
        print(f"CATALOG BLOCKED: {exc}", file=sys.stderr)
        return 1
    status.update({"ok": True, "lastError": None, "lastSuccessAt": iso(now), "warnings": warnings, **result})
    write_json(CVE_DIR / "status.json", status)
    print(f"Catalog: {result['counts']}" + (f" | warnings: {warnings}" if warnings else ""))
    return 0


def load_existing() -> dict[str, dict]:
    out = {}
    for p in CVE_DIR.glob("[0-9][0-9][0-9][0-9]/CVE-*.json"):
        r = read_json(p)
        if isinstance(r, dict) and r.get("cve"):
            out[r["cve"]] = r
    return out


def nvd_from_record(r: dict) -> dict | None:
    if r.get("nvdPending"):
        return None
    return {k: r.get(k) for k in ("published", "lastModified", "cvss", "cwes", "affected",
                                  "affectedTruncated", "references")} | {
        "status": r.get("nvdStatus"), "description": r.get("description")}


def build(now, warnings: list[str]) -> dict:
    kev = collect_kev()
    kev_by = {r["cve"]: r for r in kev["records"]}
    existing = load_existing()
    nvd_cache = {c: n for c, r in existing.items() if (n := nvd_from_record(r))}

    # ---- incremental NVD sync
    state = read_json(CVE_DIR / "state.json", {}) or {}
    cursor = C.parse_ts(state.get("nvdCursor")) or (now - timedelta(days=BACKFILL_DAYS))
    nvd_ok = True
    try:
        fresh = C.nvd_modified_since(cursor - timedelta(hours=1), now)
        for rec in fresh:
            cid = rec.get("id")
            if C.is_cve(cid):
                nvd_cache[cid] = C.parse_nvd_full(rec)
        synced = len(fresh)
    except SourceError as exc:
        nvd_ok, synced = False, 0
        warnings.append(f"NVD sync failed; using cached NVD data ({exc})"[:300])

    # ---- universe
    brief_cves, appears = brief_appearances()
    universe = set(kev_by) | set(brief_cves)
    universe |= {c for c, n in nvd_cache.items() if C.keep_non_kev(n, now, RETAIN_DAYS)}

    # ---- per-CVE NVD lookups for KEV/brief CVEs still missing NVD data
    missing = sorted((c for c in universe if c not in nvd_cache), reverse=True)
    key = os.environ.get("NVD_API_KEY", "").strip()
    limit = int(os.environ.get("TW_NVD_LOOKUPS") or (400 if key else 40))
    pause = 0 if os.environ.get("TW_FIXTURES") else (0.7 if key else 6.5)
    looked = 0
    for cid in missing[:limit] if nvd_ok else []:
        try:
            raw = fetch_json(f"{NVD_URL}?cveId={cid}", headers={"apiKey": key} if key else {}, retries=2)
            vulns = raw.get("vulnerabilities") if isinstance(raw, dict) else None
            if vulns:
                nvd_cache[cid] = C.parse_nvd_full(vulns[0].get("cve", {}))
            looked += 1
        except SourceError:
            pass
        time.sleep(pause)
    universe = {c for c in universe if c in nvd_cache or c in kev_by}  # brief CVE with neither: skip

    # ---- detections
    nuclei_dir = os.environ.get("TW_NUCLEI_DIR")
    commit = os.environ.get("TW_NUCLEI_COMMIT") or None
    if nuclei_dir and Path(nuclei_dir).is_dir():
        nuclei = index_nuclei(Path(nuclei_dir), commit)
        write_json(VAL_DIR / "nuclei-index.json",
                   {"repo": "projectdiscovery/nuclei-templates", "commit": commit,
                    "indexedAt": iso(now), "count": sum(map(len, nuclei.values())), "templates": nuclei})
        nuclei_meta = {"commit": commit, "indexedAt": iso(now)}
    else:
        cached = read_json(VAL_DIR / "nuclei-index.json", {}) or {}
        nuclei = cached.get("templates", {})
        nuclei_meta = {"commit": cached.get("commit"), "indexedAt": cached.get("indexedAt")}
        if nuclei_dir:
            warnings.append("Nuclei template checkout unavailable; using cached index")
    reviews = load_reviews(read_json(VAL_DIR / "reviews.json", {"entries": []}))
    detections = merge(nuclei, reviews)

    # ---- EPSS (single file)
    epss_path = CVE_DIR / "epss.json"
    try:
        epss = collect_epss(sorted(universe))
        epss_date = next((e["date"] for e in epss.values() if e.get("date")), None)
        write_json(epss_path, {"date": epss_date, "fetchedAt": iso(now),
                               "note": "Probability estimate; not evidence of exploitation.",
                               "scores": {c: [e["score"], e["percentile"]] for c, e in sorted(epss.items())}})
    except SourceError as exc:
        warnings.append(f"EPSS refresh failed; previous scores kept ({exc})"[:300])

    # ---- records
    records, errs = {}, []
    for cid in universe:
        nvd = nvd_cache.get(cid)
        prov = {
            "nvd": {"url": f"https://nvd.nist.gov/vuln/detail/{cid}", "lastModified": (nvd or {}).get("lastModified")} if nvd else None,
            "kev": {"url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "catalogVersion": kev.get("catalogVersion"), "fetchedAt": kev["fetchedAt"]} if cid in kev_by else None,
            "detections": {"source": "projectdiscovery/nuclei-templates", "commitInStatus": True} if cid in nuclei else None,
        }
        r = C.build_record(cid, nvd, kev_by.get(cid), detections.get(cid, []), appears.get(cid, {}), prov)
        errs += C.validate_record(r)
        records[cid] = r
    if errs:
        raise ValueError("Catalog quality gate failed:\n  - " + "\n  - ".join(errs[:30]))
    if len(records) < len(kev_by):
        raise ValueError("Catalog smaller than KEV catalog — refusing to publish")

    # ---- write (only changed files), prune removed
    written = 0
    for cid, r in records.items():
        path = CVE_DIR / cid.split("-")[1] / f"{cid}.json"
        old = existing.get(cid)
        if old != json.loads(json.dumps(r)):
            write_json(path, r)
            written += 1
    removed = 0
    for cid in set(existing) - set(records):
        (CVE_DIR / cid.split("-")[1] / f"{cid}.json").unlink(missing_ok=True)
        removed += 1
    rows = sorted((C.index_row(r) for r in records.values()), key=lambda x: (x[8] or "", x[0]), reverse=True)
    write_json(CVE_DIR / "index.json", {"schemaVersion": 1, "generatedAt": iso(now), "fields": C.INDEX_FIELDS,
                                        "count": len(rows), "items": rows})
    if nvd_ok:
        write_json(CVE_DIR / "state.json", {"nvdCursor": iso(now)})
    pending = sum(1 for r in records.values() if r["nvdPending"])
    if pending:
        warnings.append(f"{pending} KEV CVEs awaiting NVD enrichment (filled over the next runs)")
    return {
        "coverage": (f"All CISA KEV CVEs, CVEs with CVSS ≥ 7.0 published in the last {RETAIN_DAYS} days, "
                     "and every CVE featured in a ThreatWatch brief."),
        "counts": {"total": len(records), "kev": len(kev_by), "withDetection": sum(1 for r in records.values() if r["detections"]),
                   "nvdPending": pending, "nvdSynced": synced, "nvdLookups": looked,
                   "written": written, "removed": removed},
        "sources": {"kevCatalogVersion": kev.get("catalogVersion"), "nucleiCommit": nuclei_meta.get("commit"),
                    "nucleiIndexedAt": nuclei_meta.get("indexedAt"),
                    "nvdSyncOk": nvd_ok},
    }


def brief_appearances() -> tuple[set[str], dict[str, dict]]:
    appears: dict[str, dict] = {}
    for p in sorted((DATA_DIR / "briefs").glob("????-??-??.json")):
        b = read_json(p, {}) or {}
        for c in b.get("cves", []):
            appears.setdefault(c["cve"], {}).setdefault("briefs", []).append(p.stem)
    for p in sorted((DATA_DIR / "monthly").glob("????-??.json")):
        m = read_json(p, {}) or {}
        for e in m.get("events", []):
            months = appears.setdefault(e["cve"], {}).setdefault("months", [])
            if p.stem not in months:
                months.append(p.stem)
    briefs = {c for c, a in appears.items() if a.get("briefs")}
    return briefs, appears


if __name__ == "__main__":
    sys.exit(main())
