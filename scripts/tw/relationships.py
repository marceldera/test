"""Threat Map data from MITRE ATT&CK (replaces the former demonstration dataset).

Graph: ATT&CK group --attributed--> ATT&CK campaign --exploits--> CVE (named in the campaign's ATT&CK record)
                                    ATT&CK campaign --uses-->     exploitation technique (T1190, T1203, ...)
Every edge carries evidence: the ATT&CK record URL, the first cited report where ATT&CK provides one, the
record's modification date as reportDate, and the campaign's first/last-seen dates. Nothing is inferred
beyond what ATT&CK states; industry and geography links are not generated because ATT&CK does not
structure them.
"""
from __future__ import annotations

import re
from typing import Any

from .common import safe_url

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
EXPLOIT_TECHNIQUES = {"T1190", "T1203", "T1210", "T1211", "T1212", "T1068", "T1133", "T1189", "T1195"}


def _ext(obj: dict, source: str = "mitre-attack") -> dict:
    for r in obj.get("external_references") or []:
        if r.get("source_name") == source:
            return r
    return {}


def _first_citation(obj: dict) -> str | None:
    for r in obj.get("external_references") or []:
        if r.get("source_name") != "mitre-attack" and safe_url(r.get("url")):
            return r["url"]
    return None


def _day(ts: Any) -> str | None:
    return str(ts)[:10] if ts else None


def build_graph(bundle: dict, cve_info: dict[str, dict], version: str | None, now_iso: str) -> dict:
    objs = {o["id"]: o for o in bundle.get("objects", []) if not o.get("revoked") and not o.get("x_mitre_deprecated")}
    rels = [o for o in objs.values() if o.get("type") == "relationship"]
    campaigns = {i: o for i, o in objs.items() if o.get("type") == "campaign"}

    camp_cves: dict[str, set[str]] = {}
    for cid, c in campaigns.items():
        found = set(CVE_RE.findall(c.get("description") or ""))
        for r in rels:
            if r.get("source_ref") == cid:
                found |= set(CVE_RE.findall(r.get("description") or ""))
        if found:
            camp_cves[cid] = found

    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add_edge(src, dst, relation, why, url, report, first=None, last=None, conf="moderate", etype="MITRE ATT&CK"):
        u = safe_url(url)
        if not u or not report:
            return
        edges.append({"id": f"e{len(edges) + 1}", "source": src, "target": dst, "relation": relation, "confidence": conf,
                      "why": why, "evidence": {"type": etype, "url": u, "reportDate": report, "firstObserved": first,
                                               "lastObserved": last,
                                               "provenance": f"MITRE ATT&CK Enterprise {version or ''}".strip()}})

    for cid, cves in sorted(camp_cves.items(), key=lambda kv: _ext(campaigns[kv[0]]).get("external_id", "")):
        c = campaigns[cid]
        ref = _ext(c)
        cnode = f"k-{ref.get('external_id', cid)}"
        first, last = _day(c.get("first_seen")), _day(c.get("last_seen"))
        nodes[cnode] = {"id": cnode, "type": "campaign", "label": c.get("name", ref.get("external_id")),
                        "attackId": ref.get("external_id"), "url": safe_url(ref.get("url")),
                        "timeframe": f"{first or '?'} to {last or '?'}"}
        camp_url = ref.get("url")
        for cve in sorted(cves):
            info = cve_info.get(cve) or {}
            vnode = f"c-{cve}"
            nodes.setdefault(vnode, {"id": vnode, "type": "cve", "label": cve, "product": info.get("product"),
                                     "exploitation": "confirmed" if info.get("kev") else "reported",
                                     "kev": bool(info.get("kev")), "epss": info.get("epss"), "cvss": info.get("cvss")})
            add_edge(cnode, vnode, "exploits", f"The ATT&CK record for {nodes[cnode]['label']} names {cve} as exploited in the campaign.",
                     camp_url, _day(c.get("modified")), first, last,
                     conf="high" if info.get("kev") else "moderate")
        for r in rels:
            if r.get("source_ref") != cid:
                continue
            tgt = objs.get(r.get("target_ref")) or {}
            if r.get("relationship_type") == "attributed-to" and tgt.get("type") == "intrusion-set":
                g = _ext(tgt)
                anode = f"a-{g.get('external_id', tgt['id'])}"
                nodes.setdefault(anode, {"id": anode, "type": "actor", "label": tgt.get("name"),
                                         "aliases": [a for a in tgt.get("aliases") or [] if a != tgt.get("name")][:6],
                                         "classification": None, "motivation": None, "origin": None,
                                         "profile": safe_url(g.get("url")), "attackId": g.get("external_id")})
                add_edge(anode, cnode, "attributed", f"MITRE ATT&CK attributes {nodes[cnode]['label']} to {tgt.get('name')}.",
                         _first_citation(r) or camp_url, _day(r.get("modified")), first, last)
            elif r.get("relationship_type") == "uses" and tgt.get("type") == "attack-pattern":
                t = _ext(tgt)
                tid = t.get("external_id", "")
                if tid.split(".")[0] not in EXPLOIT_TECHNIQUES:
                    continue
                tnode = f"t-{tid}"
                nodes.setdefault(tnode, {"id": tnode, "type": "technique", "label": f"{tid} {tgt.get('name')}",
                                         "url": safe_url(t.get("url"))})
                add_edge(cnode, tnode, "uses", f"ATT&CK records {nodes[cnode]['label']} using {tid}.",
                         _first_citation(r) or camp_url, _day(r.get("modified")), first, last)
    return {
        "schemaVersion": 1,
        "dataset": {"status": "verified",
                    "label": f"Relationships from MITRE ATT&CK Enterprise {version or ''}: groups, their campaigns, the CVEs those "
                             "campaigns exploited and the exploitation techniques they used. Each link cites its ATT&CK record.",
                    "updatedAt": now_iso, "source": "https://attack.mitre.org/campaigns/"},
        "nodes": list(nodes.values()),
        "edges": edges,
    }
