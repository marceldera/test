"""Collectors for public sources: CISA KEV, FIRST EPSS, NVD CVE API 2.0.

Every value carries provenance. Missing values stay None and are rendered
as "Unknown" — nothing is estimated or back-filled.
"""
from __future__ import annotations

import os
import time
from datetime import date
from typing import Any

from .common import SourceError, fetch_json, is_cve, iso, now_utc, safe_url

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

KEV_REQUIRED = ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded")


# ---------------------------------------------------------------- CISA KEV
def collect_kev() -> dict[str, Any]:
    raw = fetch_json(KEV_URL)
    if not isinstance(raw, dict) or not isinstance(raw.get("vulnerabilities"), list):
        raise SourceError("KEV schema changed: 'vulnerabilities' list missing")
    records, rejected = [], 0
    for item in raw["vulnerabilities"]:
        if not isinstance(item, dict) or not all(item.get(k) for k in KEV_REQUIRED):
            rejected += 1
            continue
        if not is_cve(item["cveID"]):
            rejected += 1
            continue
        try:
            date.fromisoformat(item["dateAdded"])
        except (TypeError, ValueError):
            rejected += 1
            continue
        ransomware = str(item.get("knownRansomwareCampaignUse", "")).strip().lower()
        records.append({
            "cve": item["cveID"],
            "vendor": str(item["vendorProject"]).strip(),
            "product": str(item["product"]).strip(),
            "name": str(item["vulnerabilityName"]).strip(),
            "dateAdded": item["dateAdded"],
            "dueDate": item.get("dueDate") or None,
            "description": str(item.get("shortDescription") or "").strip() or None,
            "requiredAction": str(item.get("requiredAction") or "").strip() or None,
            "ransomware": "known" if ransomware == "known" else "unknown",
            "cwes": [c for c in item.get("cwes") or [] if isinstance(c, str)],
            "notes": [u for u in (safe_url(n.strip()) for n in str(item.get("notes") or "").split(";")) if u],
        })
    if not records:
        raise SourceError("KEV returned zero valid records")
    if rejected > max(25, len(records) * 0.05):
        raise SourceError(f"KEV rejected {rejected} malformed records — refusing to publish")
    return {
        "catalogVersion": raw.get("catalogVersion"),
        "dateReleased": raw.get("dateReleased"),
        "fetchedAt": iso(now_utc()),
        "url": KEV_PAGE,
        "rejected": rejected,
        "records": records,
    }


# ---------------------------------------------------------------- FIRST EPSS
def collect_epss(cves: list[str]) -> dict[str, dict]:
    """Return {cve: {score, percentile, date}}; missing CVEs simply absent."""
    out: dict[str, dict] = {}
    cves = sorted({c for c in cves if is_cve(c)})
    for i in range(0, len(cves), 100):
        chunk = cves[i:i + 100]
        raw = fetch_json(f"{EPSS_URL}?cve={','.join(chunk)}")
        for row in (raw or {}).get("data", []) if isinstance(raw, dict) else []:
            try:
                out[row["cve"]] = {
                    "score": round(float(row["epss"]), 5),
                    "percentile": round(float(row["percentile"]), 5),
                    "date": row.get("date"),
                }
            except (KeyError, TypeError, ValueError):
                continue
    return out


# ---------------------------------------------------------------- NVD
def collect_nvd(cves: list[str], limit: int = 40) -> dict[str, dict]:
    """Per-CVE NVD lookup. Rate limits: 5 req/30s without key, 50 with key."""
    key = os.environ.get("NVD_API_KEY", "").strip()
    headers = {"apiKey": key} if key else {}
    pause = 0 if os.environ.get("TW_FIXTURES") else (0.7 if key else 6.5)
    out: dict[str, dict] = {}
    for cve in [c for c in cves if is_cve(c)][:limit]:
        try:
            raw = fetch_json(f"{NVD_URL}?cveId={cve}", headers=headers, retries=2)
        except SourceError:
            continue  # NVD lag/outage is normal; fields stay Unknown
        vulns = raw.get("vulnerabilities") if isinstance(raw, dict) else None
        if vulns:
            out[cve] = _parse_nvd(vulns[0].get("cve", {}))
        time.sleep(pause)
    return out


def _parse_nvd(rec: dict) -> dict:
    metrics = rec.get("metrics") or {}
    cvss = None
    for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        rows = metrics.get(key) or []
        primary = next((r for r in rows if r.get("type") == "Primary"), rows[0] if rows else None)
        if primary and primary.get("cvssData"):
            d = primary["cvssData"]
            cvss = {
                "version": version,
                "score": d.get("baseScore"),
                "severity": d.get("baseSeverity"),
                "vector": d.get("vectorString"),
                "attackVector": d.get("attackVector"),
                "privileges": d.get("privilegesRequired"),
                "userInteraction": d.get("userInteraction"),
                "source": primary.get("source"),
            }
            break
    desc = next((d.get("value") for d in rec.get("descriptions", []) if d.get("lang") == "en"), None)
    refs = []
    for r in rec.get("references", [])[:12]:
        u = safe_url(r.get("url"))
        if u:
            refs.append({"url": u, "tags": [t for t in r.get("tags", []) if isinstance(t, str)]})
    return {
        "published": rec.get("published"),
        "lastModified": rec.get("lastModified"),
        "status": rec.get("vulnStatus"),
        "description": desc,
        "cvss": cvss,
        "references": refs,
        "url": f"https://nvd.nist.gov/vuln/detail/{rec.get('id')}",
    }
