"""Quality gates. A failing gate blocks publication; the last good edition stays live."""
from __future__ import annotations

from typing import Any

from .common import is_cve, safe_url

PRIORITIES = {"emergency", "urgent", "routine", "monitor"}
CONFIDENCE = {"high", "moderate", "low"}


def validate_brief(b: Any) -> list[str]:
    errs: list[str] = []
    if not isinstance(b, dict):
        return ["brief is not an object"]
    for k in ("schemaVersion", "edition", "publishedAt", "window", "executive", "actions",
              "cves", "changes", "sources", "coverage"):
        if k not in b:
            errs.append(f"missing key: {k}")
    if errs:
        return errs
    if len(b["actions"]) > 5:
        errs.append("more than five top actions")
    cve_ids = set()
    for c in b["cves"]:
        cid = c.get("cve")
        if not is_cve(cid):
            errs.append(f"invalid CVE id: {cid!r}")
            continue
        cve_ids.add(cid)
        if c.get("priority") not in PRIORITIES:
            errs.append(f"{cid}: bad priority")
        if not c.get("sources") or not all(safe_url(s.get("url")) for s in c["sources"]):
            errs.append(f"{cid}: missing or unsafe source URL")
        if not c.get("rationale"):
            errs.append(f"{cid}: missing rationale")
        e = c.get("epss")
        if e is not None and not (0 <= e.get("score", -1) <= 1 and 0 <= e.get("percentile", -1) <= 1):
            errs.append(f"{cid}: EPSS out of range")
        s = (c.get("cvss") or {}).get("score")
        if s is not None and not (0 <= float(s) <= 10):
            errs.append(f"{cid}: CVSS out of range")
    for a in b["actions"]:
        if a.get("cve") not in cve_ids:
            errs.append(f"action references CVE not in brief: {a.get('cve')}")
        if not a.get("evidence") or not all(safe_url(u) for u in a["evidence"]):
            errs.append(f"action {a.get('rank')}: missing evidence")
    for key in ("campaigns", "industries", "actors"):
        sec = b.get(key) or {}
        for it in sec.get("items", []):
            if not it.get("sources") or not all(safe_url(u) for u in it["sources"]):
                errs.append(f"{key}: item without https source")
            if it.get("confidence") not in CONFIDENCE:
                errs.append(f"{key}: item without confidence")
    counts = b["executive"].get("counts", {})
    if counts.get("kevAdded", 0) < len(b["cves"]):
        errs.append("counts do not reconcile with CVE list")
    return errs


def validate_month(m: Any) -> list[str]:
    errs: list[str] = []
    if not isinstance(m, dict) or len(m.get("metrics", [])) != 4:
        return ["monthly summary must have exactly four metrics"]
    for mt in m["metrics"]:
        for k in ("label", "value", "rule", "source", "window", "updatedAt"):
            if k not in mt:
                errs.append(f"metric {mt.get('id')}: missing {k}")
    by_id = {mt["id"]: mt["value"] for mt in m["metrics"]}
    ev = m.get("events", [])
    if by_id.get("kev_added") != len(ev):
        errs.append("kev_added metric does not reconcile with event list")
    if by_id.get("ransomware") != sum(e["ransomware"] == "known" for e in ev):
        errs.append("ransomware metric does not reconcile")
    if by_id.get("vendors") != len({e["vendor"].lower() for e in ev}):
        errs.append("vendor metric does not reconcile")
    for e in ev:
        if not is_cve(e.get("cve")) or not safe_url(e.get("source")):
            errs.append(f"bad monthly event {e.get('cve')}")
    return errs


def validate_relationships(g: Any) -> list[str]:
    errs: list[str] = []
    if not isinstance(g, dict):
        return ["graph is not an object"]
    status = g.get("dataset", {}).get("status")
    if status not in ("demo", "verified"):
        errs.append("dataset.status must be 'demo' or 'verified'")
    nodes = {n.get("id"): n for n in g.get("nodes", [])}
    kinds = {"actor", "campaign", "cve", "industry", "geography", "technique"}
    allowed = {("actor", "campaign"), ("campaign", "cve"), ("campaign", "industry"),
               ("campaign", "geography"), ("actor", "technique"), ("campaign", "technique")}
    for nid, n in nodes.items():
        if n.get("type") not in kinds:
            errs.append(f"node {nid}: bad type")
        if n.get("type") == "cve" and status == "verified" and not is_cve(n.get("label")):
            errs.append(f"node {nid}: CVE label invalid")
    for e in g.get("edges", []):
        s, t = nodes.get(e.get("source")), nodes.get(e.get("target"))
        if not s or not t:
            errs.append(f"edge {e.get('id')}: dangling endpoint")
            continue
        if (s["type"], t["type"]) not in allowed:
            errs.append(f"edge {e.get('id')}: {s['type']}→{t['type']} not allowed (use campaign evidence)")
        if e.get("confidence") not in CONFIDENCE:
            errs.append(f"edge {e.get('id')}: confidence required")
        if e.get("relation") not in ("observed_targeting", "possible_exposure", "uses", "exploits", "attributed"):
            errs.append(f"edge {e.get('id')}: relation required")
        if status == "verified":
            ev = e.get("evidence") or {}
            if not safe_url(ev.get("url")) or not ev.get("reportDate"):
                errs.append(f"edge {e.get('id')}: verified edge needs evidence.url and reportDate")
    return errs
