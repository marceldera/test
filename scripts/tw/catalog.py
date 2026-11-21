"""Public CVE catalog for Vulnerability Validation (Phase 1, read-only).

Coverage (by design, stated on the page):
  * every CVE in the CISA KEV catalog;
  * CVEs with CVSS >= 7.0 published within RETAIN_DAYS, found via an
    incremental NVD lastModified sync;
  * every CVE that appeared in a ThreatWatch daily brief.

Each CVE is one JSON file (changes only when NVD/KEV change). EPSS lives in a
single epss.json so daily score updates don't rewrite thousands of files.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote

from .common import SourceError, UTC, fetch_json, is_cve, iso, safe_url
from .sources import NVD_URL, _parse_nvd

SCHEMA_VERSION = 1
NVD_PAGE = 2000
NVD_MAX_WINDOW = timedelta(days=119)
MIN_CVSS = 7.0


def _nvd_time(dt: datetime) -> str:
    return quote(dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000+00:00"), safe="")


def nvd_modified_since(start: datetime, end: datetime) -> list[dict]:
    """All non-rejected NVD CVE records modified in [start, end], paginated."""
    key = os.environ.get("NVD_API_KEY", "").strip()
    headers = {"apiKey": key} if key else {}
    pause = 0 if os.environ.get("TW_FIXTURES") else (0.7 if key else 6.5)
    out: list[dict] = []
    win_start = start
    while win_start < end:
        win_end = min(end, win_start + NVD_MAX_WINDOW)
        index = 0
        while True:
            url = (f"{NVD_URL}?lastModStartDate={_nvd_time(win_start)}&lastModEndDate={_nvd_time(win_end)}"
                   f"&resultsPerPage={NVD_PAGE}&startIndex={index}&noRejected")
            raw = fetch_json(url, headers=headers, retries=4, backoff=10)
            if not isinstance(raw, dict) or "vulnerabilities" not in raw:
                raise SourceError("NVD bulk response missing 'vulnerabilities'")
            page = [v.get("cve", {}) for v in raw["vulnerabilities"]]
            out.extend(page)
            total = int(raw.get("totalResults", 0))
            index += len(page)
            if not page or index >= total:
                break
            time.sleep(pause)
        win_start = win_end
        time.sleep(pause)
    return out


def parse_nvd_full(rec: dict) -> dict:
    """NVD record -> catalog fields (CVSS, CPE configuration, tagged references)."""
    base = _parse_nvd(rec)
    affected, truncated = [], False
    for conf in rec.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                parts = str(m.get("criteria", "")).split(":")
                if len(parts) < 6:
                    continue
                vendor, product, version = parts[3], parts[4], parts[5]
                rng = []
                if m.get("versionStartIncluding"):
                    rng.append(f">= {m['versionStartIncluding']}")
                if m.get("versionStartExcluding"):
                    rng.append(f"> {m['versionStartExcluding']}")
                if m.get("versionEndIncluding"):
                    rng.append(f"<= {m['versionEndIncluding']}")
                if m.get("versionEndExcluding"):
                    rng.append(f"< {m['versionEndExcluding']}")
                if not rng:
                    rng.append("all versions" if version in ("*", "-") else f"= {version}")
                item = {"vendor": vendor, "product": product, "versions": ", ".join(rng)}
                if item not in affected:
                    if len(affected) >= 25:
                        truncated = True
                        continue
                    affected.append(item)
    refs = []
    for r in rec.get("references", [])[:40]:
        u = safe_url(r.get("url"))
        if u:
            refs.append({"url": u, "tags": [t for t in r.get("tags", []) if isinstance(t, str)]})
    cwes = sorted({d.get("value") for w in rec.get("weaknesses", []) for d in w.get("description", [])
                   if str(d.get("value", "")).startswith("CWE-")})
    return {
        "published": base["published"], "lastModified": base["lastModified"], "status": base["status"],
        "description": base["description"], "cvss": base["cvss"], "cwes": cwes,
        "affected": affected, "affectedTruncated": truncated, "references": refs,
    }


def build_record(cve: str, nvd: dict | None, kev: dict | None, detections: list[dict],
                 appears: dict, prov: dict) -> dict:
    nvd = nvd or {}
    refs = nvd.get("references", [])
    exploit_refs = [r["url"] for r in refs if "Exploit" in r["tags"]][:6]
    fix_refs = [r for r in refs if set(r["tags"]) & {"Patch", "Mitigation"}][:6]
    vendor_refs = [r for r in refs if "Vendor Advisory" in r["tags"]][:6]
    affected = nvd.get("affected") or []
    vendor = kev["vendor"] if kev else (affected[0]["vendor"].replace("_", " ").title() if affected else None)
    product = kev["product"] if kev else (affected[0]["product"].replace("_", " ").title() if affected else None)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "cve": cve,
        "vendor": vendor,
        "product": product,
        "title": kev["name"] if kev else None,
        "description": nvd.get("description") or (kev or {}).get("description"),
        "published": nvd.get("published"),
        "lastModified": nvd.get("lastModified"),
        "nvdStatus": nvd.get("status"),
        "nvdPending": not nvd,
        "cvss": nvd.get("cvss"),
        "cwes": nvd.get("cwes") or (kev or {}).get("cwes") or [],
        "affected": affected,
        "affectedTruncated": nvd.get("affectedTruncated", False),
        "kev": ({"dateAdded": kev["dateAdded"], "dueDate": kev["dueDate"], "ransomware": kev["ransomware"],
                 "requiredAction": kev["requiredAction"]} if kev else None),
        "exploitStatus": {
            "kevListed": bool(kev),
            "publicExploitReference": bool(exploit_refs),
            "reportedExploitation": "CISA KEV" if kev else None,
            "note": "KEV listing, public exploit references and scanner signals are separate evidence; none proves a specific asset is compromised.",
        },
        "exploitRefs": exploit_refs,
        "fixRefs": fix_refs,
        "vendorRefs": vendor_refs,
        "references": refs[:20],
        "detections": detections,
        "appearsIn": appears,
        "provenance": prov,
    }


def index_row(r: dict) -> list:
    cv = r.get("cvss") or {}
    return [r["cve"], r.get("vendor") or "", r.get("product") or "", cv.get("score"),
            (cv.get("severity") or "").upper() or None, 1 if r["kev"] else 0,
            1 if any(d["reviewStatus"] != "rejected" for d in r["detections"]) else 0,
            1 if r["exploitStatus"]["publicExploitReference"] else 0,
            (r.get("published") or "")[:10] or None,
            1 if r["fixRefs"] else 0]


INDEX_FIELDS = ["cve", "vendor", "product", "cvss", "severity", "kev", "detection",
                "exploitRef", "published", "fixRef"]


def keep_non_kev(nvd: dict, now: datetime, retain_days: int) -> bool:
    score = (nvd.get("cvss") or {}).get("score")
    pub = nvd.get("published")
    if score is None or score < MIN_CVSS or not pub:
        return False
    try:
        published = datetime.fromisoformat(pub.replace("Z", "+00:00"))
    except ValueError:
        return False
    if published.tzinfo is None:
        published = published.replace(tzinfo=UTC)
    return published >= now - timedelta(days=retain_days)


def validate_record(r: Any) -> list[str]:
    errs = []
    if not isinstance(r, dict) or not is_cve(r.get("cve")):
        return ["record without valid cve"]
    c = r["cve"]
    cv = r.get("cvss")
    if cv is not None and cv.get("score") is not None and not (0 <= float(cv["score"]) <= 10):
        errs.append(f"{c}: CVSS out of range")
    for k in ("exploitRefs",):
        if not all(safe_url(u) for u in r.get(k, [])):
            errs.append(f"{c}: unsafe {k}")
    for k in ("fixRefs", "vendorRefs", "references"):
        if not all(safe_url(x.get("url")) for x in r.get(k, [])):
            errs.append(f"{c}: unsafe {k}")
    for d in r.get("detections", []):
        if d.get("url") is not None and not safe_url(d["url"]):
            errs.append(f"{c}: unsafe detection url")
        if d.get("reviewStatus") not in ("reviewed", "unreviewed", "rejected"):
            errs.append(f"{c}: bad detection reviewStatus")
    if r.get("nvdPending") and not r.get("kev"):
        errs.append(f"{c}: record has neither NVD nor KEV data")
    return errs


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        return None


__all__ = ["nvd_modified_since", "parse_nvd_full", "build_record", "index_row", "INDEX_FIELDS",
           "keep_non_kev", "validate_record", "parse_ts", "iso"]
