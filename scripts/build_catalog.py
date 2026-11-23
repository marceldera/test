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

  validation/intel-*.json       last good copy of each enrichment feed

Coverage: every CVE published in the last TW_RETAIN_DAYS (90), every CISA KEV CVE,
every zero-day / exploited CVE from Google Project Zero, ENISA EUVD and VulnCheck KEV,
and every CVE featured in a brief. Each record carries public exploit / PoC links,
threat-intelligence context and MITRE ATT&CK mappings (see tw/intel.py).

Env: NVD_API_KEY (optional), VULNCHECK_API_KEY (optional), TW_NUCLEI_DIR + TW_NUCLEI_COMMIT,
     TW_NVD_BACKFILL_DAYS (14), TW_RETAIN_DAYS (90), TW_MIN_CVSS (0), TW_NVD_LOOKUPS (auto),
     TW_INTEL_FETCH (1), TW_POC_DIR (optional local PoC-in-GitHub checkout).
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
from tw import intel as I  # noqa: E402
from tw.common import DATA_DIR, SourceError, fetch_json, fetch_text, iso, now_utc, read_json, write_json  # noqa: E402
from tw.detections import combine, index_nmap, index_nuclei, load_reviews, merge  # noqa: E402
from tw.playbooks import load_playbooks, load_products  # noqa: E402
from tw.sources import NVD_URL, collect_epss, collect_kev  # noqa: E402

CVE_DIR = DATA_DIR / "cves"
VAL_DIR = DATA_DIR / "validation"
BACKFILL_DAYS = int(os.environ.get("TW_NVD_BACKFILL_DAYS", "14"))
RETAIN_DAYS = int(os.environ.get("TW_RETAIN_DAYS", "90"))
SCOPE_VERSION = 2  # 2 = every CVE published in the window (backfilled once by publish date)


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


def cached_source(name: str, label: str, fn, warnings: list[str], meta: dict, keep: set[str] | None = None) -> dict:
    """Run one enrichment collector; on failure fall back to its last good copy."""
    path = VAL_DIR / f"intel-{name}.json"
    old = read_json(path, {}) or {}
    try:
        data = fn()
        if keep is not None:
            data = {k: v for k, v in data.items() if k in keep}
        if json.loads(json.dumps(data)) != old.get("data"):  # rewrite only when content changed
            write_json(path, {"source": label, "count": len(data), "data": data})
        meta[name] = {"ok": True, "count": len(data)}
        return data
    except (SourceError, ValueError, KeyError, TypeError) as exc:
        warnings.append(f"{label} unavailable; kept last good copy ({exc})"[:300])
        meta[name] = {"ok": False, "count": len(old.get("data") or {})}
        return old.get("data") or {}


def build(now, warnings: list[str]) -> dict:
    kev = collect_kev()
    kev_by = {r["cve"]: r for r in kev["records"]}
    intel_on = os.environ.get("TW_INTEL_FETCH", "1") == "1"
    src: dict[str, dict] = {}
    imeta: dict[str, dict] = {}

    # ---- zero-day / exploited-in-the-wild sources (they define part of the universe)
    if intel_on:
        src["p0"] = cached_source("project-zero", "Google Project Zero 0day In the Wild",
                                  lambda: I.collect_project_zero(now.year), warnings, imeta)
        src["euvd"] = cached_source("euvd", "ENISA EUVD exploited", I.collect_euvd, warnings, imeta)
        vc_key = os.environ.get("VULNCHECK_API_KEY", "").strip()
        if vc_key:
            src["vulncheck"] = cached_source("vulncheck", "VulnCheck KEV", lambda: I.collect_vulncheck(vc_key),
                                             warnings, imeta)
        else:
            imeta["vulncheck"] = {"ok": None, "count": 0, "note": "set VULNCHECK_API_KEY to enable"}
    exploited = I.exploited_set(src)
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

    # ---- one-time backfill when the coverage rule widens: every CVE *published* in the window
    scope = state.get("scope")
    if nvd_ok and scope != SCOPE_VERSION:
        try:
            pub = C.nvd_modified_since(now - timedelta(days=RETAIN_DAYS), now, field="pub")
            for rec in pub:
                cid = rec.get("id")
                if C.is_cve(cid):
                    nvd_cache[cid] = C.parse_nvd_full(rec)
            synced += len(pub)
            scope = SCOPE_VERSION
        except SourceError as exc:
            warnings.append(f"NVD {RETAIN_DAYS}-day backfill failed; will retry next run ({exc})"[:300])

    # ---- universe
    brief_cves, appears = brief_appearances()
    universe = set(kev_by) | set(brief_cves) | exploited
    universe |= {c for c, n in nvd_cache.items() if C.keep_non_kev(n, now, RETAIN_DAYS)}

    # ---- per-CVE NVD lookups for KEV / zero-day / brief CVEs still missing NVD data (zero-days first)
    missing = sorted((c for c in universe if c not in nvd_cache), key=lambda c: (c not in (src.get("p0") or {}), c not in kev_by,
                                             [-int(x) for x in c.split("-")[1:]]))
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
    universe = {c for c in universe if c in nvd_cache or c in kev_by or c in exploited}  # brief CVE with neither: skip

    # ---- public exploits / PoCs and ATT&CK (links and metadata only; nothing is executed)
    if intel_on:
        src["msf"] = cached_source("metasploit", "Metasploit module metadata",
                                   lambda: I.index_metasploit(fetch_json(I.MSF_URL, retries=2, timeout=120)),
                                   warnings, imeta, keep=universe)
        src["edb"] = cached_source("exploitdb", "Exploit-DB index",
                                   lambda: I.index_exploitdb(fetch_text(I.EDB_URL, retries=2)),
                                   warnings, imeta, keep=universe)
        if not os.environ.get("TW_FIXTURES") or os.environ.get("TW_POC_DIR"):
            src["github"] = cached_source("github-poc", "PoC-in-GitHub",
                                          lambda: I.collect_github_pocs(universe), warnings, imeta, keep=universe)
        else:
            src["github"] = {}

        attack_bundle: dict = {}

        def _attack():
            bundle = json.loads(fetch_text(I.ATTACK_URL, retries=2))
            data, version = I.index_attack(bundle)
            imeta["attackVersion"] = version
            attack_bundle["bundle"], attack_bundle["version"] = bundle, version
            return data
        src["attack"] = cached_source("attack", "MITRE ATT&CK Enterprise", _attack, warnings, imeta)
        src["ctid"] = cached_source("ctid-kev", "CTID KEV→ATT&CK mappings",
                                    lambda: I.index_ctid(fetch_json(I.CTID_URL, retries=2, timeout=120)), warnings, imeta)

    # ---- detections
    nuclei_dir = os.environ.get("TW_NUCLEI_DIR")
    commit = os.environ.get("TW_NUCLEI_COMMIT") or None
    live_fetch = not os.environ.get("TW_FIXTURES") and os.environ.get("TW_NUCLEI_FETCH", "1") == "1"
    if not nuclei_dir and live_fetch:
        nuclei_dir, commit = sparse_fetch("https://github.com/projectdiscovery/nuclei-templates.git",
                                          "/*/cves/**", "Nuclei templates", warnings)
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
    nmap_dir = os.environ.get("TW_NMAP_DIR")
    nmap_commit = os.environ.get("TW_NMAP_COMMIT") or None
    if not nmap_dir and live_fetch:
        nmap_dir, nmap_commit = sparse_fetch("https://github.com/nmap/nmap.git", "scripts",
                                             "Nmap NSE scripts", warnings)
    if nmap_dir and Path(nmap_dir).is_dir():
        nmap = index_nmap(Path(nmap_dir))
        write_json(VAL_DIR / "nmap-index.json", {"repo": "nmap/nmap", "commit": nmap_commit, "indexedAt": iso(now),
                                                 "count": sum(map(len, nmap.values())), "scripts": nmap})
        nuclei_meta["nmapCommit"] = nmap_commit
    else:
        cached_n = read_json(VAL_DIR / "nmap-index.json", {}) or {}
        nmap = cached_n.get("scripts", {})
        nuclei_meta["nmapCommit"] = cached_n.get("commit")
    reviews = load_reviews(read_json(VAL_DIR / "reviews.json", {"entries": []}))
    detections = merge(combine(nuclei, nmap), reviews)
    playbooks = load_playbooks(read_json(VAL_DIR / "playbooks.json", {"playbooks": []}))
    load_products(read_json(VAL_DIR / "products.json", {"products": []}))

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
            "detections": {"source": "nuclei-templates / nmap", "commitInStatus": True} if cid in detections else None,
        }
        fb = (src.get("p0") or {}).get(cid) or (src.get("vulncheck") or {}).get(cid)
        r = C.build_record(cid, nvd, kev_by.get(cid), detections.get(cid, []), appears.get(cid, {}), prov, fb)
        r.update(I.assemble(cid, kev_by.get(cid), src, r["exploitRefs"]))
        ex = r["exploitStatus"]
        ex["publicExploitReference"] = r["pocs"]["count"] > 0
        ex["reportedExploitation"] = ", ".join(s["source"] for s in r["exploitation"]["sources"]) or None
        ex["note"] = ("Exploitation reports, public exploit / PoC code and scanner signals are separate evidence; "
                      "none proves a specific asset is vulnerable or compromised. PoC repositories are unvetted.")
        r["curatedPlaybook"] = cid in playbooks
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
    # ---- Threat Map: sourced relationships from MITRE ATT&CK (keeps the last good file on any failure)
    try:
        bundle = (locals().get("attack_bundle") or {}).get("bundle")
        if bundle:
            from tw.relationships import build_graph
            from tw.validate import validate_relationships
            info = {r["cve"]: {"product": f"{r.get('vendor') or ''} {r.get('product') or ''}".strip() or None,
                               "kev": bool((r.get("kev") or {}).get("dateAdded")) if isinstance(r.get("kev"), dict) else bool(r.get("kev")),
                               "cvss": (r.get("cvss") or {}).get("score") if isinstance(r.get("cvss"), dict) else r.get("cvss")}
                    for r in records.values()}
            graph = build_graph(bundle, info, attack_bundle.get("version"), iso(now))
            gerrs = validate_relationships(graph)
            if gerrs or not graph["edges"]:
                warnings.append("Threat Map not rebuilt: " + "; ".join(gerrs[:3] or ["no ATT&CK campaign links"]))
            else:
                write_json(DATA_DIR / "relationships.json", graph)
    except Exception as exc:  # never block the catalog on the map
        warnings.append(f"Threat Map not rebuilt: {exc}")

    write_json(CVE_DIR / "index.json", {"schemaVersion": 1, "generatedAt": iso(now), "fields": C.INDEX_FIELDS,
                                        "count": len(rows), "items": rows})
    if nvd_ok:
        write_json(CVE_DIR / "state.json", {"nvdCursor": iso(now), "scope": scope})
    pending = sum(1 for r in records.values() if r["nvdPending"])
    if pending:
        warnings.append(f"{pending} exploited CVEs awaiting NVD enrichment (filled over the next runs)")
    return {
        "coverage": (f"Every CVE published in the last {RETAIN_DAYS} days"
                     + (f" with CVSS ≥ {C.MIN_CVSS:g}" if C.MIN_CVSS > 0 else "")
                     + ", every CISA KEV CVE, every zero-day tracked by Google Project Zero, exploited CVEs "
                       "reported by ENISA EUVD" + (" and VulnCheck KEV" if src.get("vulncheck") else "")
                     + ", and every CVE featured in a ThreatWatch brief."),
        "counts": {"total": len(records), "kev": len(kev_by),
                   "zeroDay": sum(1 for r in records.values() if r["exploitation"]["zeroDay"]),
                   "inTheWild": sum(1 for r in records.values() if r["exploitation"]["inTheWild"]),
                   "withPoc": sum(1 for r in records.values() if r["pocs"]["count"]),
                   "withAttack": sum(1 for r in records.values() if r["attack"]["techniques"] or r["intel"]["groups"]),
                   "withDetection": sum(1 for r in records.values() if r["detections"]),
                   "nvdPending": pending, "nvdSynced": synced, "nvdLookups": looked,
                   "written": written, "removed": removed},
        "sources": {"kevCatalogVersion": kev.get("catalogVersion"), "nucleiCommit": nuclei_meta.get("commit"),
                    "nucleiIndexedAt": nuclei_meta.get("indexedAt"), "nmapCommit": nuclei_meta.get("nmapCommit"),
                    "curatedPlaybooks": len(playbooks), "intel": imeta,
                    "nvdSyncOk": nvd_ok},
    }


def sparse_fetch(repo: str, pattern: str, label: str, warnings: list[str]) -> tuple[str | None, str | None]:
    """Shallow sparse clone of public *metadata* (templates/scripts are indexed, never executed)."""
    import subprocess
    import tempfile
    dest = Path(tempfile.mkdtemp(prefix="twsrc-")) / "repo"
    cmds = [["git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--sparse", repo, str(dest)],
            ["git", "-C", str(dest), "sparse-checkout", "set", "--no-cone", pattern]]
    try:
        for c in cmds:
            subprocess.run(c, check=True, timeout=600, capture_output=True)
        commit = subprocess.run(["git", "-C", str(dest), "rev-parse", "--short", "HEAD"], check=True,
                                capture_output=True, text=True, timeout=30).stdout.strip()
        return str(dest), commit
    except (OSError, subprocess.SubprocessError) as exc:
        warnings.append(f"Could not fetch {label}; using cached index ({type(exc).__name__})")
        return None, None


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
