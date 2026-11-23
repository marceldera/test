"""AEGIS Global Threat Intelligence — record model, editorial rules and public-data build.

Source of truth: one JSON file per event in global-intelligence/editorial/records/<ID>.json.
`build()` validates every record and writes the public files the static dashboard reads:

  global-intelligence/data/active-threats.json      published events that are not resolved/archived
  global-intelligence/data/historical-threats.json  resolved or archived events (kept forever)
  global-intelligence/data/signals.json             Emerging Global Security Signals
  global-intelligence/data/executive-summary.json   counts + a 200-300 word summary computed from records
  global-intelligence/data/last-updated.json        collection time vs. last editorial verification time

Editorial rules enforced here (spec §6-§8, §13):
  * every published record has dates, sources, evidence status, priority rationale and an update history;
  * CRITICAL/HIGH priority and CONFIRMED evidence need editorial approval (approved_by / approved_at);
  * CONFIRMED evidence needs >= 2 genuinely independent sources (syndicated copies count once);
  * update history and corrections are append-only: an entry already published can never change or vanish;
  * links must be https; nothing but structured text reaches the page (rendered with textContent);
  * demonstration records can never be published alongside live records.
Only records with publication_status published / updated / archived appear publicly.
"""
from __future__ import annotations

import json
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

REGIONS = ["Africa", "Asia-Pacific", "Europe", "Middle East", "North America", "Latin America", "Global"]
CATEGORIES = ["Geopolitical", "Military", "Cybersecurity", "AI", "Critical Infrastructure", "Humanitarian",
              "Environmental"]
PRIORITIES = ["CRITICAL", "HIGH", "MODERATE", "LOW"]
EVIDENCE = ["Confirmed", "Reported", "Disputed", "Analytical Assessment"]
TRENDS = ["Escalating", "Stable", "De-escalating", "Resolved"]
WORKFLOW = ["collected", "analyzed", "verification_pending", "approved", "published", "updated", "archived"]
PUBLIC_STATUSES = {"published", "updated", "archived"}
SOURCE_TYPES = ["primary", "official", "international_org", "news", "research", "humanitarian", "advisory"]
HISTORY_TYPES = ["published", "substantive", "evidence_status", "priority", "trend", "correction", "resolved"]
RECORD_TYPES = ["event", "signal"]
ID_RE = re.compile(r"^GI-(?:DEMO-)?\d{4}-\d{3,4}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
MAX_TEXT = 4000


class RecordError(ValueError):
    pass


# ------------------------------------------------------------------ helpers
def _https(u: Any) -> str | None:
    if not isinstance(u, str) or not u.startswith("https://") or any(c in u for c in ' "<>\\\n\r\t'):
        return None
    return u if len(u) <= 2000 else None


def _date(v: Any, field: str, rid: str) -> str:
    try:
        return date.fromisoformat(str(v)[:10]).isoformat() if len(str(v)) == 10 else _ts(v, field, rid)
    except ValueError as exc:
        raise RecordError(f"{rid}: {field} is not a valid date: {v!r}") from exc


def _ts(v: Any, field: str, rid: str) -> str:
    try:
        dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError as exc:
        raise RecordError(f"{rid}: {field} is not a valid ISO date/time: {v!r}") from exc
    if dt.tzinfo is None:
        raise RecordError(f"{rid}: {field} needs a timezone (e.g. 2026-11-23T07:00:00-05:00)")
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _day(v: str) -> date:
    return date.fromisoformat(v[:10])


def _text(v: Any, field: str, rid: str, required: bool = True, max_len: int = MAX_TEXT) -> str:
    if v is None or (isinstance(v, str) and not v.strip()):
        if required:
            raise RecordError(f"{rid}: {field} is required")
        return ""
    if not isinstance(v, str):
        raise RecordError(f"{rid}: {field} must be text")
    v = re.sub(r"[ \t]+", " ", v.strip())
    if len(v) > max_len:
        raise RecordError(f"{rid}: {field} is longer than {max_len} characters")
    return v


def _texts(v: Any, field: str, rid: str, min_items: int = 0) -> list[str]:
    if v is None:
        v = []
    if not isinstance(v, list):
        raise RecordError(f"{rid}: {field} must be a list")
    out = [_text(x, f"{field}[]", rid) for x in v]
    if len(out) < min_items:
        raise RecordError(f"{rid}: {field} needs at least {min_items} item(s)")
    return out


def _enum(v: Any, allowed: list[str], field: str, rid: str) -> str:
    if v not in allowed:
        raise RecordError(f"{rid}: {field} must be one of {allowed}, got {v!r}")
    return v


# ------------------------------------------------------------------ record validation
def _claims(v: Any, field: str, rid: str, n_sources: int, min_items: int = 0) -> list[dict]:
    """[{text, sources:[source indexes]}] — every claim cites at least one listed source."""
    if v is None:
        v = []
    if not isinstance(v, list):
        raise RecordError(f"{rid}: {field} must be a list")
    out = []
    for c in v:
        if not isinstance(c, dict):
            raise RecordError(f"{rid}: each {field} entry must be an object with text and sources")
        refs = c.get("sources")
        if not isinstance(refs, list) or not refs or not all(isinstance(i, int) and 0 <= i < n_sources for i in refs):
            raise RecordError(f"{rid}: {field} claim must cite source numbers 0..{n_sources - 1}: {c.get('text')!r}")
        item = {"text": _text(c.get("text"), field, rid), "sources": sorted(set(refs))}
        if c.get("attributed_to"):
            item["attributed_to"] = _text(c["attributed_to"], f"{field}.attributed_to", rid, max_len=200)
        out.append(item)
    if len(out) < min_items:
        raise RecordError(f"{rid}: {field} needs at least {min_items} item(s)")
    return out


def _sources(v: Any, rid: str) -> list[dict]:
    if not isinstance(v, list) or not v:
        raise RecordError(f"{rid}: sources must list at least one source")
    out = []
    for i, s in enumerate(v):
        if not isinstance(s, dict):
            raise RecordError(f"{rid}: sources[{i}] must be an object")
        url = _https(s.get("url"))
        if not url:
            raise RecordError(f"{rid}: sources[{i}] needs an https url")
        out.append({
            "publisher": _text(s.get("publisher"), f"sources[{i}].publisher", rid, max_len=200),
            "title": _text(s.get("title"), f"sources[{i}].title", rid, max_len=400),
            "published": _date(s.get("published"), f"sources[{i}].published", rid),
            "url": url,
            "type": _enum(s.get("type"), SOURCE_TYPES, f"sources[{i}].type", rid),
            "accessed": _date(s.get("accessed"), f"sources[{i}].accessed", rid),
            "region": _enum(s.get("region"), REGIONS, f"sources[{i}].region", rid) if s.get("region") else None,
            "state_affiliated": bool(s.get("state_affiliated")),
            # Syndicated / shared-chain copies name the original; they never count as independent corroboration.
            "syndicated_from": _text(s.get("syndicated_from"), f"sources[{i}].syndicated_from", rid,
                                     required=False, max_len=200) or None,
        })
    return out


def independent_count(sources: list[dict]) -> int:
    chains = set()
    for s in sources:
        chains.add((s.get("syndicated_from") or s["publisher"]).strip().lower())
    return len(chains)


def _history(v: Any, rid: str) -> list[dict]:
    if not isinstance(v, list) or not v:
        raise RecordError(f"{rid}: update_history needs at least the publication entry")
    out = []
    for i, h in enumerate(v):
        if not isinstance(h, dict):
            raise RecordError(f"{rid}: update_history[{i}] must be an object")
        out.append({"date": _ts(h.get("date"), f"update_history[{i}].date", rid),
                    "type": _enum(h.get("type"), HISTORY_TYPES, f"update_history[{i}].type", rid),
                    "summary": _text(h.get("summary"), f"update_history[{i}].summary", rid, max_len=1000)})
    dates = [h["date"] for h in out]
    if dates != sorted(dates):
        raise RecordError(f"{rid}: update_history must be in date order (oldest first)")
    return out


def validate_record(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise RecordError("record must be a JSON object")
    rid = raw.get("id")
    if not isinstance(rid, str) or not ID_RE.match(rid):
        raise RecordError(f"id must look like GI-2026-0001 (or GI-DEMO-2026-001), got {rid!r}")
    demo = bool(raw.get("demo"))
    if demo != rid.startswith("GI-DEMO-"):
        raise RecordError(f"{rid}: demonstration records (and only they) use GI-DEMO- ids and demo: true")
    rtype = _enum(raw.get("record_type", "event"), RECORD_TYPES, "record_type", rid)
    status = _enum(raw.get("publication_status"), WORKFLOW, "publication_status", rid)
    sources = _sources(raw.get("sources"), rid)
    regions = raw.get("regions")
    if not isinstance(regions, list) or not regions or not all(r in REGIONS for r in regions):
        raise RecordError(f"{rid}: regions must be a non-empty list from {REGIONS}")
    rec = {
        "id": rid, "demo": demo, "record_type": rtype,
        "title": _text(raw.get("title"), "title", rid, max_len=200),
        "location": _text(raw.get("location"), "location", rid, required=False, max_len=200),
        "regions": list(dict.fromkeys(regions)),
        "countries": _texts(raw.get("countries"), "countries", rid, 1),
        "primary_category": _enum(raw.get("primary_category"), CATEGORIES, "primary_category", rid),
        "secondary_categories": [_enum(c, CATEGORIES, "secondary_categories[]", rid)
                                 for c in raw.get("secondary_categories") or []],
        "priority": _enum(raw.get("priority"), PRIORITIES, "priority", rid),
        "evidence_status": _enum(raw.get("evidence_status"), EVIDENCE, "evidence_status", rid),
        "event_date": _date(raw.get("event_date"), "event_date", rid),
        "published_at": _ts(raw.get("published_at"), "published_at", rid),
        "last_verified": _ts(raw.get("last_verified"), "last_verified", rid),
        "last_substantive_update": _ts(raw.get("last_substantive_update"), "last_substantive_update", rid),
        "trend": _enum(raw.get("trend"), TRENDS, "trend", rid),
        "summary": _text(raw.get("summary"), "summary", rid),
        "confirmed_facts": _claims(raw.get("confirmed_facts"), "confirmed_facts", rid, len(sources)),
        "reported_claims": _claims(raw.get("reported_claims"), "reported_claims", rid, len(sources)),
        "international_perspectives": _claims(raw.get("international_perspectives"), "international_perspectives",
                                              rid, len(sources)),
        "impact_assessment": _text(raw.get("impact_assessment"), "impact_assessment", rid),
        "priority_rationale": _text(raw.get("priority_rationale"), "priority_rationale", rid),
        "unknowns": _texts(raw.get("unknowns"), "unknowns", rid),
        "reassessment_triggers": _texts(raw.get("reassessment_triggers"), "reassessment_triggers", rid),
        "monitoring_actions": _texts(raw.get("monitoring_actions"), "monitoring_actions", rid, 1),
        "sources": sources,
        "update_history": _history(raw.get("update_history"), rid),
        "publication_status": status,
        "approved_by": _text(raw.get("approved_by"), "approved_by", rid, required=False, max_len=120) or None,
        "approved_at": _ts(raw["approved_at"], "approved_at", rid) if raw.get("approved_at") else None,
        "threatwatch_cves": [],
    }
    if rtype == "signal":
        # Observed action and analytical interpretation are always shown separately (spec §9).
        rec["observed_action"] = _text(raw.get("observed_action"), "observed_action", rid)
        rec["interpretation"] = _text(raw.get("interpretation"), "interpretation", rid)
    for c in raw.get("threatwatch_cves") or []:
        if not isinstance(c, str) or not CVE_RE.match(c):
            raise RecordError(f"{rid}: threatwatch_cves entries must be CVE ids, got {c!r}")
        rec["threatwatch_cves"].append(c)

    # ---- editorial integrity
    if rec["evidence_status"] == "Confirmed":
        if not rec["confirmed_facts"]:
            raise RecordError(f"{rid}: Confirmed evidence status needs at least one confirmed fact")
        if independent_count(sources) < 2:
            raise RecordError(f"{rid}: Confirmed evidence needs at least two independent sources "
                              "(syndicated copies of the same report count once)")
    needs_approval = rec["priority"] in ("CRITICAL", "HIGH") or rec["evidence_status"] == "Confirmed"
    if status in PUBLIC_STATUSES | {"approved"} and needs_approval and not (rec["approved_by"] and rec["approved_at"]):
        raise RecordError(f"{rid}: {rec['priority']} priority / {rec['evidence_status']} evidence requires editorial "
                          "approval (approved_by and approved_at) before publication")
    if rtype == "signal" and rec["priority"] in ("CRITICAL", "HIGH") and not rec["priority_rationale"]:
        raise RecordError(f"{rid}: signals do not automatically receive HIGH/CRITICAL priority; justify it")
    if _day(rec["last_verified"]) < _day(rec["published_at"]) and status in PUBLIC_STATUSES:
        raise RecordError(f"{rid}: last_verified is earlier than published_at")
    if rec["trend"] == "Resolved" and rec["update_history"][-1]["type"] not in ("resolved", "correction",
                                                                                 "substantive", "trend"):
        raise RecordError(f"{rid}: a Resolved record needs an update_history entry recording the resolution")
    if status in PUBLIC_STATUSES and rec["update_history"][0]["type"] != "published":
        raise RecordError(f"{rid}: the first update_history entry must be the publication entry")
    return rec


# ------------------------------------------------------------------ history preservation
def check_history_preserved(new: dict, old: dict | None) -> list[str]:
    """Already-published history entries and corrections must survive unchanged (never silently overwritten)."""
    if not old:
        return []
    errs = []
    new_h = [(h["date"], h["type"], h["summary"]) for h in new["update_history"]]
    for h in old.get("update_history") or []:
        if (h["date"], h["type"], h["summary"]) not in new_h:
            errs.append(f"{new['id']}: published update_history entry from {h['date']} ({h['type']}) was changed or "
                        "removed; add a correction entry instead")
    for field, label in (("evidence_status", "evidence status"), ("priority", "priority"), ("trend", "trend")):
        if old.get(field) != new.get(field):
            types = {"evidence_status": "evidence_status", "priority": "priority", "trend": "trend"}
            later = [h for h in new["update_history"] if h["date"] > old.get("last_substantive_update", "")
                     and h["type"] in (types[field], "correction", "resolved")]
            if not later:
                errs.append(f"{new['id']}: {label} changed from {old.get(field)} to {new.get(field)} without a new "
                            "update_history entry")
    if old.get("published_at") != new.get("published_at"):
        errs.append(f"{new['id']}: published_at must never change once published")
    return errs


# ------------------------------------------------------------------ public outputs
PRIORITY_ORDER = {p: i for i, p in enumerate(PRIORITIES)}


def _public(rec: dict) -> dict:
    out = {k: v for k, v in rec.items() if k not in ("publication_status",)}
    out["status"] = "historical" if (rec["trend"] == "Resolved" or rec["publication_status"] == "archived") else "active"
    out["approved"] = bool(rec["approved_by"] and rec["approved_at"])
    out["independent_sources"] = independent_count(rec["sources"])
    return out


def _sort_key(r: dict):
    return (PRIORITY_ORDER[r["priority"]], [-ord(c) for c in r["last_substantive_update"]], r["id"])


def executive_summary(events: list[dict], signals: list[dict], now: datetime) -> dict:
    """Counts and a 200-300 word summary computed only from published records."""
    active = [r for r in events if r["status"] == "active"]
    since = (now - timedelta(hours=24)).isoformat().replace("+00:00", "Z")
    countries = sorted({c for r in active for c in r["countries"] if c.lower() not in ("multiple", "global")})
    by_pri = {p: [r for r in active if r["priority"] == p] for p in PRIORITIES}
    regions = {g: sum(1 for r in active if g in r["regions"]) for g in REGIONS}
    cats = {c: sum(1 for r in active if r["primary_category"] == c) for c in CATEGORIES}
    ev = {e: sum(1 for r in active if r["evidence_status"] == e) for e in EVIDENCE}
    trend = {t: sum(1 for r in active if r["trend"] == t) for t in TRENDS}
    updated24 = [r for r in active if r["last_substantive_update"] >= since]

    def names(rs):
        return "; ".join(f"{r['title']} ({', '.join(r['countries'][:2])})" for r in rs)

    reg_txt = ", ".join(f"{g} ({n})" for g, n in sorted(regions.items(), key=lambda kv: -kv[1]) if n)
    cat_txt = ", ".join(f"{c.lower() if c not in ('AI',) else c} ({n})" for c, n in
                        sorted(cats.items(), key=lambda kv: -kv[1]) if n)
    paras = []
    if not active:
        paras.append("AEGIS is not tracking any active, published global security events at this time. "
                     "Historical assessments remain available in the archive.")
    else:
        paras.append(
            f"AEGIS is tracking {len(active)} active global security "
            f"{'event' if len(active) == 1 else 'events'} across {len(countries)} "
            f"{'country or territory' if len(countries) == 1 else 'countries and territories'}. "
            f"{len(by_pri['CRITICAL'])} {'is' if len(by_pri['CRITICAL']) == 1 else 'are'} rated Critical and "
            f"{len(by_pri['HIGH'])} High; {len(by_pri['MODERATE'])} Moderate and {len(by_pri['LOW'])} Low events "
            f"are under observation. {len(updated24)} "
            f"{'event was' if len(updated24) == 1 else 'events were'} substantively updated in the last 24 hours.")
        if by_pri["CRITICAL"]:
            paras.append("Critical events: " + names(by_pri["CRITICAL"][:4]) + ".")
        if by_pri["HIGH"]:
            paras.append("High-priority events: " + names(by_pri["HIGH"][:4]) + ".")
        paras.append(f"By region, activity is recorded in {reg_txt}. By primary category: {cat_txt}.")
        paras.append(
            f"Evidence status across active events: {ev['Confirmed']} confirmed, {ev['Reported']} reported, "
            f"{ev['Disputed']} disputed and {ev['Analytical Assessment']} analytical "
            f"{'assessment' if ev['Analytical Assessment'] == 1 else 'assessments'}. "
            f"Trends: {trend['Escalating']} escalating, {trend['Stable']} stable and "
            f"{trend['De-escalating']} de-escalating.")
    if signals:
        paras.append(f"The Emerging Global Security Signals panel lists {len(signals)} observed "
                     f"{'action' if len(signals) == 1 else 'actions'}, such as preparedness guidance, exercises, "
                     "official warnings and new advisories. A signal records what was observed; it does not by itself "
                     "establish an imminent threat.")
    paras.append(
        "Priority reflects impact, evidence quality, exposure, geographic scope, observed activity and urgency, not "
        "media attention, and is kept separate from evidence status. Reported allegations remain attributed claims "
        "until supported by independent evidence. Volume of reporting about a country is not a measure of its threat "
        "level. Each assessment lists its sources, unknowns and full update history.")
    text = "\n\n".join(paras)
    return {
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "counts": {
            "active": len(active), "critical": len(by_pri["CRITICAL"]), "high": len(by_pri["HIGH"]),
            "moderate": len(by_pri["MODERATE"]), "low": len(by_pri["LOW"]), "countries": len(countries),
            "updated_24h": len(updated24), "historical": sum(1 for r in events if r["status"] == "historical"),
            "signals": len(signals),
        },
        "distribution": {"region": regions, "category": cats, "evidence": ev, "priority":
                         {p: len(v) for p, v in by_pri.items()}},
        "summary": text,
        "word_count": len(text.split()),
    }


def build(root: Path, now: datetime | None = None, write: bool = True) -> tuple[dict, list[str]]:
    """Validate all records and (optionally) write the public data files. Returns (outputs, errors)."""
    now = now or datetime.now(timezone.utc)
    rec_dir = root / "global-intelligence" / "editorial" / "records"
    data_dir = root / "global-intelligence" / "data"
    errs: list[str] = []
    records: list[dict] = []
    seen = set()
    for p in sorted(rec_dir.glob("*.json")):
        try:
            rec = validate_record(json.loads(p.read_text(encoding="utf-8")))
        except (RecordError, ValueError) as exc:
            errs.append(f"{p.name}: {exc}")
            continue
        if rec["id"] in seen:
            errs.append(f"{p.name}: duplicate id {rec['id']}")
        if p.stem != rec["id"]:
            errs.append(f"{p.name}: file name must be {rec['id']}.json")
        seen.add(rec["id"])
        records.append(rec)
    public = [r for r in records if r["publication_status"] in PUBLIC_STATUSES]
    demo = {r["demo"] for r in public}
    if len(demo) > 1:
        errs.append("demonstration records cannot be published alongside live records; archive or delete the demo "
                    "records (publication_status) before publishing live intelligence")
    # history preservation against what is already public
    prev = {}
    for name in ("active-threats.json", "historical-threats.json", "signals.json"):
        try:
            for r in json.loads((data_dir / name).read_text(encoding="utf-8")).get("records", []):
                prev[r["id"]] = r
        except (OSError, ValueError):
            pass
    pub_ids = {r["id"] for r in public}
    for rid in prev:
        if rid not in pub_ids and not prev[rid].get("demo"):
            errs.append(f"{rid}: a published record was removed; set publication_status to archived instead")
    for r in public:
        errs += check_history_preserved(r, prev.get(r["id"]))
    if errs:
        return {}, errs

    items = [_public(r) for r in public]
    events = sorted([r for r in items if r["record_type"] == "event"], key=_sort_key)
    signals = sorted([r for r in items if r["record_type"] == "signal" and r["status"] == "active"],
                     key=lambda r: r["last_substantive_update"], reverse=True)
    old_signals = [r for r in items if r["record_type"] == "signal" and r["status"] == "historical"]
    is_demo = bool(public) and all(r["demo"] for r in public)
    stamp = {"demo": is_demo, "generated_at": now.isoformat().replace("+00:00", "Z")}
    outputs = {
        "active-threats.json": {**stamp, "records": [r for r in events if r["status"] == "active"]},
        "historical-threats.json": {**stamp, "records": [r for r in events if r["status"] == "historical"] + old_signals},
        "signals.json": {**stamp, "records": signals},
        "executive-summary.json": {**stamp, **executive_summary(events, signals, now)},
        "last-updated.json": {
            **stamp,
            "collected_at": now.isoformat().replace("+00:00", "Z"),
            "last_verified": max((r["last_verified"] for r in items), default=None),
            "last_substantive_update": max((r["last_substantive_update"] for r in items), default=None),
            "reporting_date": now.astimezone(timezone(timedelta(hours=-5))).date().isoformat(),
            "pending_review": sum(1 for r in records if r["publication_status"] in
                                  ("collected", "analyzed", "verification_pending", "approved")),
            "cadence": "Daily collection at 7:00 AM Eastern. Not real-time.",
        },
    }
    if write:
        data_dir.mkdir(parents=True, exist_ok=True)
        for name, obj in outputs.items():
            tmp = data_dir / (name + ".tmp")
            tmp.write_text(json.dumps(obj, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
            tmp.replace(data_dir / name)
    return outputs, []
