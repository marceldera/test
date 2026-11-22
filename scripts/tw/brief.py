"""Compose the Daily Zero-Day Intelligence Brief and Monthly Summary.

Deterministic aggregation only. Narrative sections that need analyst judgement
(campaigns, actors, industries) come exclusively from a human-reviewed
editorial overlay file; without one they are reported as "not covered".
"""
from __future__ import annotations

from collections import Counter
from datetime import date, datetime, timedelta
from typing import Any

from .common import ET, iso, safe_url
from .sources import KEV_PAGE

SCHEMA_VERSION = 1
MAX_BRIEF_CVES = 25
EPSS_JUMP = 0.10  # absolute score change considered material


# ---------------------------------------------------------------- priority
def classify(rec: dict) -> tuple[str, str]:
    """Return (priority, rationale) for a KEV entry (exploitation is confirmed)."""
    cvss = rec.get("cvss") or {}
    score = cvss.get("score")
    av = (cvss.get("attackVector") or "").upper()
    pr = (cvss.get("privileges") or "").upper()
    ransomware = rec["kev"]["ransomware"] == "known"
    parts = ["Exploitation confirmed by CISA KEV"]
    if ransomware:
        parts.append("CISA flags known ransomware use")
    if score is None:
        parts.append("CVSS not yet available from NVD")
        return "urgent", "; ".join(parts) + "."
    parts.append(f"CVSS {cvss.get('version')} {score}")
    if av == "NETWORK" and pr == "NONE":
        parts.append("network-reachable without authentication")
    if av in ("LOCAL", "PHYSICAL") or pr == "HIGH":
        parts.append("requires local access or high privileges")
        return ("urgent" if ransomware else "routine"), "; ".join(parts) + "."
    if score >= 9.0 or (av == "NETWORK" and pr == "NONE") or (ransomware and score >= 7.0):
        return "emergency", "; ".join(parts) + "."
    return "urgent", "; ".join(parts) + "."


PRIORITY_ORDER = {"emergency": 0, "urgent": 1, "routine": 2, "monitor": 3}
RESPONSE_GUIDANCE = {
    "emergency": "Mitigate exposed instances within 24–72 hours (guidance, not policy).",
    "urgent": "Remediate within the CISA due date or your next emergency change window.",
    "routine": "Remediate in the normal patch cycle; prerequisites limit exposure.",
    "monitor": "Track for exploitation or scope changes.",
}


def _sort_key(c: dict):
    ep = (c.get("epss") or {}).get("percentile") or 0
    sc = (c.get("cvss") or {}).get("score") or 0
    return (PRIORITY_ORDER[c["priority"]], -ep, -sc, c["cve"])


# ---------------------------------------------------------------- daily
def build_daily(kev: dict, epss: dict, nvd: dict, state: dict, editorial: dict | None,
                now: datetime) -> tuple[dict, dict]:
    """Return (brief, new_state)."""
    now_et = now.astimezone(ET)
    edition = now_et.date().isoformat()
    by_id = {r["cve"]: r for r in kev["records"]}
    prev_ids = set(state.get("kevIds") or [])
    first_run = not prev_ids
    if first_run:
        cutoff = (now_et.date() - timedelta(days=1)).isoformat()
        new_ids = [c for c, r in by_id.items() if r["dateAdded"] >= cutoff]
    else:
        new_ids = [c for c in by_id if c not in prev_ids]
    window_start = state.get("lastPublishedAt") or iso(now - timedelta(hours=24))

    cves = []
    for cid in new_ids:
        cves.append(_cve_entry(by_id[cid], epss.get(cid), nvd.get(cid)))
    cves.sort(key=_sort_key)
    overflow = max(0, len(cves) - MAX_BRIEF_CVES)
    cves = cves[:MAX_BRIEF_CVES]

    # ---- material changes on previously tracked entries
    changes = [{"cve": c["cve"], "type": "kev_added",
                "detail": f"Added to CISA KEV on {c['kev']['dateAdded']}."} for c in cves]
    prev_ransom = state.get("ransomware") or {}
    prev_epss = state.get("epss") or {}
    for cid, rec in by_id.items():
        if cid in prev_ids and prev_ransom.get(cid) == "unknown" and rec["ransomware"] == "known":
            changes.append({"cve": cid, "type": "ransomware_flag",
                            "detail": f"CISA now flags known ransomware use ({rec['vendor']} {rec['product']})."})
    for cid, e in epss.items():
        old = prev_epss.get(cid)
        if old is not None and cid not in new_ids and abs(e["score"] - old) >= EPSS_JUMP:
            direction = "rose" if e["score"] > old else "fell"
            changes.append({"cve": cid, "type": "epss_change",
                            "detail": f"EPSS {direction} from {old:.2f} to {e['score']:.2f} (score date {e['date']})."})

    actions = _top_actions([c for c in cves if c["priority"] in ("emergency", "urgent")])
    remediation = {k: [c["cve"] for c in cves if c["priority"] == k] for k in PRIORITY_ORDER}
    counts = {
        "kevAdded": len(new_ids),
        "kevRansomware": sum(1 for c in new_ids if by_id[c]["ransomware"] == "known"),
        "emergency": len(remediation["emergency"]),
        "urgent": len(remediation["urgent"]),
        "criticalHigh": sum(1 for c in cves if ((c.get("cvss") or {}).get("severity") or "").upper() in ("CRITICAL", "HIGH")),
        "materialChanges": len(changes) - len(cves),
        "kevTotal": len(by_id),
    }
    unknown_fields = sorted({f for c in cves for f in c["unknown"]})

    ed = editorial or {}
    brief = {
        "schemaVersion": SCHEMA_VERSION,
        "edition": edition,
        "publishedAt": iso(now),
        "window": {"start": window_start, "end": iso(now),
                   "note": "KEV additions not present in the previous edition’s catalog snapshot."
                   if not first_run else "First edition: KEV additions dated since the previous calendar day."},
        "executive": {
            "summary": ed.get("summary") or _summary(counts, cves, overflow),
            "summarySource": "editorial" if ed.get("summary") else "generated",
            "counts": counts,
            "developments": _developments(cves, changes),
        },
        "kevLatest": _kev_latest(kev),
        "actions": actions,
        "cves": cves,
        "overflow": overflow,
        "campaigns": _section(ed, "campaigns"),
        "industries": _section(ed, "industries"),
        "actors": _section(ed, "actors"),
        "remediation": {"groups": remediation, "guidance": RESPONSE_GUIDANCE},
        "changes": changes,
        "sources": _sources(kev, epss, nvd, ed),
        "coverage": {
            "covered": ["CISA KEV additions", "FIRST EPSS", "NVD CVSS and references"],
            "notCovered": [] if ed else [
                "Campaign, threat actor and industry analysis (requires reviewed editorial input)",
                "Zero-days not yet in CISA KEV", "Vendor-specific fixed-version validation"],
            "unknownFields": unknown_fields,
            "editorial": {"present": bool(ed), "reviewedBy": ed.get("reviewedBy"),
                          "reviewedAt": ed.get("reviewedAt")},
        },
    }
    new_state = {
        "catalogVersion": kev.get("catalogVersion"),
        "kevIds": sorted(by_id),
        "ransomware": {c: r["ransomware"] for c, r in by_id.items()},
        "epss": {c: e["score"] for c, e in epss.items()},
        "lastPublishedAt": iso(now),
        "lastEdition": edition,
    }
    return brief, new_state


def _kev_latest(kev: dict) -> dict:
    """The most recent dateAdded batch in the KEV catalog (for "latest additions remain …")."""
    recs = kev.get("records") or []
    if not recs:
        return {}
    last = max(r["dateAdded"] for r in recs)
    batch = sorted((r for r in recs if r["dateAdded"] == last), key=lambda r: r["cve"])
    dues = sorted(r["dueDate"] for r in batch if r.get("dueDate"))
    return {"date": last, "dueDate": dues[0] if dues else None, "catalogVersion": kev.get("catalogVersion"),
            "released": kev.get("dateReleased"),
            "items": [{"cve": r["cve"], "vendor": r["vendor"], "product": r["product"]} for r in batch[:12]]}


def _cve_entry(rec: dict, epss: dict | None, nvd: dict | None) -> dict:
    nvd = nvd or {}
    cvss = nvd.get("cvss")
    entry = {
        "cve": rec["cve"],
        "vendor": rec["vendor"],
        "product": rec["product"],
        "name": rec["name"],
        "description": rec["description"] or nvd.get("description"),
        "kev": {"dateAdded": rec["dateAdded"], "dueDate": rec["dueDate"],
                "ransomware": rec["ransomware"], "requiredAction": rec["requiredAction"]},
        "exploitation": {"status": "Confirmed exploited",
                         "basis": "Listed in CISA KEV (dateAdded is the listing date, not first exploitation)."},
        "exploitMaturity": None,  # PoC vs weaponized: needs a reviewed source
        "cvss": cvss,
        "epss": epss,
        "affectedVersions": None,
        "fixedVersions": None,
        "cwes": rec["cwes"],
        "nvdStatus": nvd.get("status"),
    }
    entry["priority"], entry["rationale"] = classify(entry)
    srcs = [{"label": "CISA KEV", "url": KEV_PAGE}]
    if nvd.get("url"):
        srcs.append({"label": "NVD", "url": nvd["url"]})
    srcs.append({"label": "FIRST EPSS", "url": f"https://www.first.org/epss/"} if epss else None)
    for r in nvd.get("references", []):
        if set(r["tags"]) & {"Vendor Advisory", "Patch", "Mitigation"}:
            srcs.append({"label": "Vendor advisory", "url": r["url"]})
    for u in rec["notes"]:
        if all(u != s["url"] for s in srcs if s):
            srcs.append({"label": "KEV reference", "url": u})
    entry["sources"] = [s for s in srcs if s][:8]
    entry["unknown"] = [k for k, v in (("CVSS", cvss), ("EPSS", epss), ("Affected versions", None),
                                       ("Fixed versions", None), ("Exploit maturity", None)) if v is None]
    return entry


def _top_actions(cands: list[dict]) -> list[dict]:
    out = []
    for i, c in enumerate(cands[:5], 1):
        steps = []
        if c["kev"]["requiredAction"]:
            steps.append(c["kev"]["requiredAction"])
        steps.append(f"Identify internet-facing and internal {c['vendor']} {c['product']} instances.")
        steps.append("Confirm fixed versions in the vendor advisory before closing the action.")
        if c["kev"]["dueDate"]:
            steps.append(f"CISA due date for federal agencies: {c['kev']['dueDate']}.")
        out.append({"rank": i, "cve": c["cve"], "priority": c["priority"],
                    "title": f"Patch or mitigate {c['vendor']} {c['product']} ({c['cve']})",
                    "why": c["rationale"], "steps": steps,
                    "evidence": [s["url"] for s in c["sources"][:3]]})
    return out


def _summary(counts: dict, cves: list[dict], overflow: int) -> str:
    n = counts["kevAdded"]
    if n == 0:
        return ("CISA published no new Known Exploited Vulnerabilities since the previous edition. "
                "That does not mean no new threats emerged — KEV is one confirmed-exploitation source, "
                "and campaigns or zero-days outside it are not covered by today’s automated feeds.")
    vendors = Counter(c["vendor"] for c in cves).most_common(3)
    vtxt = ", ".join(v for v, _ in vendors)
    s = (f"CISA added {n} vulnerabilit{'y' if n == 1 else 'ies'} to the Known Exploited Vulnerabilities "
         f"catalog since the previous edition, affecting {vtxt}. ")
    if counts["emergency"]:
        s += (f"{counts['emergency']} meet the emergency criteria (confirmed exploitation plus critical "
              "severity or unauthenticated network exposure). ")
    if counts["kevRansomware"]:
        s += f"{counts['kevRansomware']} carr{'ies' if counts['kevRansomware'] == 1 else 'y'} a known-ransomware-use flag. "
    if overflow:
        s += f"{overflow} lower-priority additions are listed in the CISA catalog only. "
    return s.strip()


def _developments(cves: list[dict], changes: list[dict]) -> list[str]:
    out = [f"{c['cve']} — {c['vendor']} {c['product']}: {c['name']} ({c['priority']})" for c in cves[:3]]
    out += [f"{ch['cve']}: {ch['detail']}" for ch in changes if ch["type"] != "kev_added"][:2]
    return out


def _section(ed: dict, key: str) -> dict:
    items = ed.get(key) or []
    if items:
        return {"status": "editorial", "items": items}
    return {"status": "not_covered", "items": [],
            "note": "No reviewed, source-linked intelligence for this section in today’s edition."}


def _sources(kev: dict, epss: dict, nvd: dict, ed: dict) -> list[dict]:
    out = [{"name": "CISA Known Exploited Vulnerabilities", "url": KEV_PAGE,
            "version": kev.get("catalogVersion"), "released": kev.get("dateReleased"),
            "fetchedAt": kev["fetchedAt"], "status": "ok"},
           {"name": "FIRST EPSS", "url": "https://www.first.org/epss/",
            "fetchedAt": kev["fetchedAt"], "status": "ok" if epss else "no data",
            "note": "Probability estimate; not evidence of exploitation."},
           {"name": "NVD CVE API 2.0", "url": "https://nvd.nist.gov/",
            "fetchedAt": kev["fetchedAt"], "status": "ok" if nvd else "no data",
            "note": "Enrichment can lag publication by days."}]
    for s in ed.get("sources") or []:
        out.append(s)
    return out


# ---------------------------------------------------------------- monthly
def build_month(kev: dict, epss: dict, month: str, now: datetime) -> dict:
    rows = sorted((r for r in kev["records"] if r["dateAdded"].startswith(month)),
                  key=lambda r: (r["dateAdded"], r["cve"]))
    high_epss = [r for r in rows if (epss.get(r["cve"]) or {}).get("percentile", 0) >= 0.90]
    epss_date = next((e["date"] for e in epss.values() if e.get("date")), None)
    y, m = map(int, month.split("-"))
    first = date(y, m, 1)
    last = (date(y + (m == 12), m % 12 + 1, 1) - timedelta(days=1))
    window = f"{first.isoformat()} to {min(last, now.astimezone(ET).date()).isoformat()} (dateAdded, ET calendar)"
    updated = iso(now)
    metrics = [
        {"id": "kev_added", "label": "New KEV entries", "value": len(rows),
         "rule": "CVE entries whose CISA dateAdded falls in the month.", "source": "CISA KEV"},
        {"id": "vendors", "label": "Distinct vendors", "value": len({r['vendor'].lower() for r in rows}),
         "rule": "Unique vendorProject values among the month’s KEV entries.", "source": "CISA KEV"},
        {"id": "ransomware", "label": "Known ransomware use", "value": sum(r["ransomware"] == "known" for r in rows),
         "rule": "Month’s KEV entries where CISA sets knownRansomwareCampaignUse = Known.", "source": "CISA KEV"},
        {"id": "epss90", "label": "EPSS ≥ 90th percentile", "value": len(high_epss),
         "rule": f"Month’s KEV entries with EPSS percentile ≥ 0.90 (scores as of {epss_date or 'unknown'}).",
         "source": "FIRST EPSS"},
    ]
    for mt in metrics:
        mt.update({"window": window, "updatedAt": updated})
    return {
        "schemaVersion": SCHEMA_VERSION,
        "month": month,
        "complete": last < now.astimezone(ET).date(),
        "updatedAt": updated,
        "metrics": metrics,
        "notice": "These are CISA KEV catalog counts, not a count of total cyber incidents.",
        "events": [{
            "date": r["dateAdded"], "cve": r["cve"], "vendor": r["vendor"], "product": r["product"],
            "concern": r["name"], "ransomware": r["ransomware"],
            "epssPercentile": (epss.get(r["cve"]) or {}).get("percentile"),
            "confidence": "Exploitation confirmed (CISA KEV); attribution not assessed",
            "source": KEV_PAGE,
        } for r in rows],
    }


def recent_months(now: datetime, n: int = 6) -> list[str]:
    d = now.astimezone(ET).date().replace(day=1)
    out = []
    for _ in range(n):
        out.append(d.strftime("%Y-%m"))
        d = (d - timedelta(days=1)).replace(day=1)
    return out


def safe_editorial(raw: Any) -> dict | None:
    """Accept editorial overlay only if every item carries https sources."""
    if not isinstance(raw, dict):
        return None
    out: dict[str, Any] = {}
    if not raw.get("reviewedBy") or not raw.get("reviewedAt"):
        raise ValueError("Editorial overlay must include reviewedBy and reviewedAt")
    out["reviewedBy"], out["reviewedAt"] = str(raw["reviewedBy"]), str(raw["reviewedAt"])
    if raw.get("summary"):
        out["summary"] = str(raw["summary"])
    for key in ("campaigns", "industries", "actors"):
        items = []
        for it in raw.get(key) or []:
            srcs = [u for u in (safe_url(s) for s in it.get("sources", [])) if u]
            if not srcs:
                raise ValueError(f"Editorial {key} item '{it.get('name')}' has no https source")
            if it.get("confidence") not in ("high", "moderate", "low"):
                raise ValueError(f"Editorial {key} item '{it.get('name')}' needs confidence high|moderate|low")
            items.append({**it, "sources": srcs})
        if items:
            out[key] = items
    if raw.get("report") is not None:
        from .report import safe_report_editorial
        out["report"] = safe_report_editorial(raw["report"])
    for s in raw.get("sources") or []:
        if safe_url(s.get("url")):
            out.setdefault("sources", []).append({"name": str(s.get("name")), "url": s["url"],
                                                  "status": "editorial"})
    return out
