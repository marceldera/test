"""Zero-day, exploit/PoC and threat-intelligence enrichment (standard library only).

Every collector returns plain data keyed by CVE and raises SourceError on failure,
so the caller can keep the last good cached copy (validation/intel-*.json).

Sources
  Zero-day / exploited-in-the-wild
    * Google Project Zero "0day In the Wild" tracking sheet (public CSV export)
    * ENISA EUVD exploited vulnerabilities (public API)
    * VulnCheck KEV (free community API; only when VULNCHECK_API_KEY is set)
    * CISA KEV is collected in sources.py
  Public exploits / PoCs (links only; nothing is downloaded or run)
    * Metasploit Framework module metadata
    * Exploit-DB index (files_exploits.csv)
    * nomi-sec/PoC-in-GitHub (unvetted GitHub repositories)
    * VulnCheck XDB links (with VulnCheck KEV)
  Threat intelligence / MITRE ATT&CK
    * MITRE ATT&CK Enterprise STIX: groups, campaigns, software and techniques whose
      ATT&CK text cites the CVE
    * Center for Threat-Informed Defense Mappings Explorer: KEV -> ATT&CK techniques
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

from .common import SourceError, fetch_json, fetch_text, is_cve, safe_url

CVE_FIND = re.compile(r"CVE-\d{4}-\d{4,7}")
URL_FIND = re.compile(r"https://[^\s\"'<>,)]+")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

P0_SHEET = "1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY"
P0_CSV = "https://docs.google.com/spreadsheets/d/" + P0_SHEET + "/gviz/tq?tqx=out:csv&sheet={sheet}"
P0_PAGE = "https://docs.google.com/spreadsheets/d/" + P0_SHEET
# /api/search honours exploited=true (~1,700 records, Nov 2026); /api/vulnerabilities ignores it and returns all ~245k.
EUVD_URL = "https://euvdservices.enisa.europa.eu/api/search?exploited=true&page={page}&size=100"
EUVD_MAX_TOTAL = 20000
VULNCHECK_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev?limit=100&page={page}"
MSF_URL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
MSF_BLOB = "https://github.com/rapid7/metasploit-framework/blob/master"
EDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
CTID_URL = os.environ.get("TW_CTID_KEV_URL") or (
    "https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/"
    "mappings/kev/attack-16.1/kev-07.28.2025/enterprise/kev-07.28.2025_attack-16.1-enterprise.json")
POC_REPO = "https://github.com/nomi-sec/PoC-in-GitHub.git"

MSF_RANK = {600: "excellent", 500: "great", 400: "good", 300: "normal", 200: "average", 100: "low", 0: "manual"}
GITHUB_TOP = 5
EDB_TOP = 8


def _min(n: int) -> int:
    """Sanity floor for feed sizes (relaxed for offline fixture tests)."""
    return 1 if os.environ.get("TW_FIXTURES") else n


def _clean(v, n: int = 300) -> str | None:
    v = (v or "").strip()
    return None if not v or v in ("???", "?", "-", "N/A", "n/a") else v[:n]


def _date(v) -> str | None:
    v = (v or "").strip()[:10]
    return v if DATE_RE.match(v) else None


def _first_url(*cells) -> str | None:
    for c in cells:
        for u in URL_FIND.findall(c or ""):
            if safe_url(u):
                return u
    return None


# ----------------------------------------------------------------- Project Zero
def parse_p0_csv(text: str) -> dict[str, dict]:
    rows = list(csv.reader(io.StringIO(text)))
    hdr_i = next((i for i, r in enumerate(rows[:20]) if r and r[0].strip().upper() == "CVE"), None)
    if hdr_i is None:
        return {}
    hdr = [h.strip().lower() for h in rows[hdr_i]]

    def col(r, *names):
        for n in names:
            if n in hdr and hdr.index(n) < len(r):
                return r[hdr.index(n)]
        return ""

    out: dict[str, dict] = {}
    for r in rows[hdr_i + 1:]:
        if not r:
            continue
        for cid in CVE_FIND.findall(r[0]):
            if cid in out:
                continue
            out[cid] = {
                "vendor": _clean(col(r, "vendor"), 80), "product": _clean(col(r, "product"), 120),
                "type": _clean(col(r, "type"), 80), "description": _clean(col(r, "description"), 300),
                "discovered": _date(col(r, "date discovered")), "patched": _date(col(r, "date patched")),
                "advisoryUrl": _first_url(col(r, "advisory")),
                "analysisUrl": _first_url(col(r, "analysis url")),
                "rcaUrl": _first_url(col(r, "root cause analysis")),
                "reportedBy": _clean(col(r, "reported by"), 300),
            }
    return out


def collect_project_zero(year: int) -> dict[str, dict]:
    data = parse_p0_csv(fetch_text(P0_CSV.format(sheet="All")))
    if len(data) < _min(50):  # "All" tab missing or renamed: read the year tabs
        for y in range(2014, year + 1):
            try:
                for k, v in parse_p0_csv(fetch_text(P0_CSV.format(sheet=y), retries=2)).items():
                    data.setdefault(k, v)
            except SourceError:
                continue
    if len(data) < _min(50):
        raise SourceError(f"Project Zero sheet returned only {len(data)} CVEs")
    return data


# ----------------------------------------------------------------- ENISA EUVD
def _euvd_date(v) -> str | None:
    if not v:
        return None
    for fmt in ("%b %d, %Y, %I:%M:%S %p", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(str(v)[:26].strip(), fmt).date().isoformat()
        except ValueError:
            continue
    return _date(str(v))


def collect_euvd(max_pages: int = 40) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for page in range(max_pages):
        raw = fetch_json(EUVD_URL.format(page=page), retries=2)
        items = raw.get("items") if isinstance(raw, dict) else raw
        if not isinstance(items, list):
            raise SourceError("EUVD response missing items")
        total = raw.get("total") if isinstance(raw, dict) else None
        if isinstance(total, int) and total > EUVD_MAX_TOTAL:
            raise SourceError(f"EUVD returned {total} records for exploited=true; filter not applied, refusing")
        for it in items:
            aliases = it.get("aliases") or ""
            if isinstance(aliases, list):
                aliases = " ".join(map(str, aliases))
            eid = str(it.get("id") or "")
            for cid in CVE_FIND.findall(aliases):
                out.setdefault(cid, {"euvdId": eid[:40] or None,
                                     "exploitedSince": _euvd_date(it.get("exploitedSince")),
                                     "url": safe_url(f"https://euvd.enisa.europa.eu/vulnerability/{eid}") if eid else None})
        if len(items) < 100:
            break
    if not out:
        raise SourceError("EUVD returned no exploited CVEs")
    return out


# ----------------------------------------------------------------- VulnCheck KEV
def collect_vulncheck(token: str, max_pages: int = 100) -> dict[str, dict]:
    out: dict[str, dict] = {}
    page, total = 1, 1
    while page <= min(total, max_pages):
        raw = fetch_json(VULNCHECK_URL.format(page=page), headers={"Authorization": f"Bearer {token}"}, retries=2)
        if not isinstance(raw, dict) or not isinstance(raw.get("data"), list):
            raise SourceError("VulnCheck KEV response missing data")
        total = int((raw.get("_meta") or {}).get("total_pages") or 1)
        for it in raw["data"]:
            xdb = [{"url": u, "type": _clean(x.get("exploit_type"), 40), "added": _date(x.get("date_added"))}
                   for x in (it.get("vulncheck_xdb") or [])[:5] if (u := safe_url(x.get("xdb_url")))]
            reports = [{"url": u, "added": _date(x.get("date_added"))}
                       for x in (it.get("vulncheck_reported_exploitation") or [])[:8] if (u := safe_url(x.get("url")))]
            for cid in it.get("cve") or []:
                if is_cve(cid):
                    out[cid] = {"dateAdded": _date(it.get("date_added")),
                                "ransomware": _clean(it.get("knownRansomwareCampaignUse"), 20),
                                "vendor": _clean(it.get("vendorProject"), 80), "product": _clean(it.get("product"), 120),
                                "name": _clean(it.get("vulnerabilityName"), 200), "xdb": xdb, "reports": reports}
        page += 1
    if not out:
        raise SourceError("VulnCheck KEV returned no CVEs")
    return out


# ----------------------------------------------------------------- exploits / PoCs
def index_metasploit(raw: dict) -> dict[str, list[dict]]:
    if not isinstance(raw, dict) or len(raw) < _min(1000):
        raise SourceError("Metasploit metadata looks incomplete")
    out: dict[str, list[dict]] = {}
    for m in raw.values():
        cves = {r for r in m.get("references") or [] if is_cve(r)}
        if not cves:
            continue
        path = str(m.get("path") or "")
        item = {"name": _clean(m.get("name"), 160), "module": _clean(m.get("fullname"), 160),
                "type": _clean(m.get("type"), 20), "rank": MSF_RANK.get(m.get("rank"), None),
                "check": bool(m.get("check")), "disclosed": _date(m.get("disclosure_date")),
                "url": safe_url(MSF_BLOB + path) if path.startswith("/modules/") else None}
        for c in cves:
            out.setdefault(c, []).append(item)
    return out


def index_exploitdb(text: str) -> dict[str, list[dict]]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or "codes" not in reader.fieldnames:
        raise SourceError("Exploit-DB index missing 'codes' column")
    out: dict[str, list[dict]] = {}
    for r in reader:
        cves = set(CVE_FIND.findall(r.get("codes") or ""))
        eid = (r.get("id") or "").strip()
        if not cves or not eid.isdigit():
            continue
        item = {"id": int(eid), "title": _clean(r.get("description"), 200), "type": _clean(r.get("type"), 20),
                "platform": _clean(r.get("platform"), 30), "verified": (r.get("verified") or "").strip() == "1",
                "published": _date(r.get("date_published")), "url": f"https://www.exploit-db.com/exploits/{eid}"}
        for c in cves:
            out.setdefault(c, []).append(item)
    if len(out) < _min(1000):
        raise SourceError("Exploit-DB index looks incomplete")
    return {c: sorted(v, key=lambda x: (not x["verified"], -x["id"]))[:EDB_TOP] for c, v in out.items()}


def parse_poc_file(data) -> tuple[list[dict], int]:
    repos = [r for r in data if isinstance(r, dict) and not r.get("fork")] if isinstance(data, list) else []
    repos.sort(key=lambda r: (-(r.get("stargazers_count") or 0), r.get("full_name") or ""))
    top = []
    for r in repos[:GITHUB_TOP]:
        u = safe_url(r.get("html_url"))
        if u and u.startswith("https://github.com/"):
            top.append({"repo": _clean(r.get("full_name"), 120), "url": u, "stars": int(r.get("stargazers_count") or 0),
                        "updated": _date(r.get("pushed_at")), "description": _clean(r.get("description"), 200)})
    return top, len(repos)


def collect_github_pocs(cves: set[str]) -> dict[str, dict]:
    """Sparse-checkout only <year>/<CVE>.json for the catalog's CVEs (metadata only)."""
    local = os.environ.get("TW_POC_DIR")
    root = Path(local) if local else Path(tempfile.mkdtemp(prefix="twpoc-")) / "repo"
    if not local:
        try:
            subprocess.run(["git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--sparse", POC_REPO, str(root)],
                           check=True, timeout=900, capture_output=True)
            patterns = "\n".join(f"/{c.split('-')[1]}/{c}.json" for c in sorted(cves)) + "\n"
            subprocess.run(["git", "-C", str(root), "sparse-checkout", "set", "--no-cone", "--stdin"],
                           input=patterns.encode(), check=True, timeout=1800, capture_output=True)
        except (OSError, subprocess.SubprocessError) as exc:
            raise SourceError(f"PoC-in-GitHub checkout failed ({type(exc).__name__})") from exc
    out: dict[str, dict] = {}
    for c in cves:
        p = root / c.split("-")[1] / f"{c}.json"
        if p.is_file():
            try:
                top, n = parse_poc_file(json.loads(p.read_text(encoding="utf-8")))
            except (ValueError, OSError):
                continue
            if n:
                out[c] = {"top": top, "total": n}
    return out


# ----------------------------------------------------------------- MITRE ATT&CK
ATTACK_KIND = {"intrusion-set": "groups", "campaign": "campaigns", "malware": "software", "tool": "software"}


def _ext(o: dict) -> tuple[str | None, str | None]:
    for r in o.get("external_references") or []:
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id"), safe_url(r.get("url"))
    return None, None


def index_attack(bundle: dict) -> tuple[dict[str, dict], str | None]:
    """CVE -> ATT&CK groups / campaigns / software / techniques whose ATT&CK text cites the CVE."""
    objs = {o["id"]: o for o in bundle.get("objects", []) if isinstance(o, dict) and "id" in o
            and not o.get("revoked") and not o.get("x_mitre_deprecated")}
    if len(objs) < _min(1000):
        raise SourceError("ATT&CK bundle looks incomplete")
    version = next((o.get("x_mitre_version") for o in objs.values() if o.get("type") == "x-mitre-collection"), None)

    def ent(o):
        xid, url = _ext(o)
        return {"id": xid, "name": _clean(o.get("name"), 120), "url": url} if xid else None

    attributed: dict[str, list[str]] = {}
    for o in objs.values():
        if o.get("type") == "relationship" and o.get("relationship_type") == "attributed-to":
            attributed.setdefault(o.get("source_ref"), []).append(o.get("target_ref"))

    out: dict[str, dict] = {}

    def add(cid, bucket, o, how):
        e = ent(o)
        if not e:
            return
        rec = out.setdefault(cid, {"groups": [], "campaigns": [], "software": [], "techniques": []})
        if not any(x["id"] == e["id"] for x in rec[bucket]):
            rec[bucket].append(e | ({"via": how} if bucket == "techniques" else {}))

    for o in objs.values():
        t = o.get("type")
        text = o.get("description") or ""
        cves = set(CVE_FIND.findall(text))
        if not cves:
            continue
        if t == "relationship" and o.get("relationship_type") == "uses":
            src, tgt = objs.get(o.get("source_ref")), objs.get(o.get("target_ref"))
            for cid in cves:
                if src and src.get("type") in ATTACK_KIND:
                    add(cid, ATTACK_KIND[src["type"]], src, "")
                    for g in attributed.get(src["id"], []):
                        if objs.get(g, {}).get("type") == "intrusion-set":
                            add(cid, "groups", objs[g], "")
                if tgt and tgt.get("type") == "attack-pattern":
                    add(cid, "techniques", tgt, f"ATT&CK: {(src or {}).get('name') or 'procedure example'}")
        elif t in ATTACK_KIND:
            for cid in cves:
                add(cid, ATTACK_KIND[t], o, "")
        elif t == "attack-pattern":
            for cid in cves:
                add(cid, "techniques", o, "ATT&CK technique description")
    return out, version


def index_ctid(raw: dict) -> dict[str, list[dict]]:
    objs = raw.get("mapping_objects") if isinstance(raw, dict) else None
    if not isinstance(objs, list) or len(objs) < _min(100):
        raise SourceError("CTID KEV mapping looks incomplete")
    out: dict[str, list[dict]] = {}
    for m in objs:
        cid, tid = m.get("capability_id"), str(m.get("attack_object_id") or "")
        if not is_cve(cid) or not re.match(r"^T\d{4}(\.\d{3})?$", tid) or m.get("status") not in (None, "complete"):
            continue
        lst = out.setdefault(cid, [])
        if not any(x["id"] == tid for x in lst):
            lst.append({"id": tid, "name": _clean(m.get("attack_object_name"), 120),
                        "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
                        "mappingType": _clean(m.get("mapping_type"), 40), "via": "CTID KEV mapping",
                        "comment": _clean(m.get("comments"), 300)})
    return out


# ----------------------------------------------------------------- record assembly
def assemble(cid: str, kev: dict | None, src: dict, nvd_exploit_refs: list[str]) -> dict:
    """Build the exploitation / pocs / intel / attack sections for one CVE record."""
    p0 = (src.get("p0") or {}).get(cid)
    eu = (src.get("euvd") or {}).get(cid)
    vc = (src.get("vulncheck") or {}).get(cid)
    sources = []
    if kev:
        sources.append({"source": "CISA KEV", "date": kev.get("dateAdded"),
                        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"})
    if p0:
        sources.append({"source": "Google Project Zero (0day In the Wild)", "date": p0.get("discovered") or p0.get("patched"),
                        "url": P0_PAGE})
    if vc:
        sources.append({"source": "VulnCheck KEV", "date": vc.get("dateAdded"), "url": "https://vulncheck.com/kev"})
    if eu:
        sources.append({"source": "ENISA EUVD (exploited)", "date": eu.get("exploitedSince"),
                        "url": eu.get("url") or "https://euvd.enisa.europa.eu/"})

    msf = (src.get("msf") or {}).get(cid, [])
    edb = (src.get("edb") or {}).get(cid, [])
    gh = (src.get("github") or {}).get(cid) or {}
    pocs = {"metasploit": msf[:6], "exploitdb": edb, "github": gh.get("top", []), "githubTotal": gh.get("total", 0),
            "vulncheckXdb": (vc or {}).get("xdb", []), "nvdTagged": nvd_exploit_refs[:6]}
    poc_count = len(msf) + len(edb) + gh.get("total", 0) + len(pocs["vulncheckXdb"]) + len(nvd_exploit_refs)

    att = (src.get("attack") or {}).get(cid) or {}
    techniques = [dict(t) for t in att.get("techniques", [])]
    for t in (src.get("ctid") or {}).get(cid, []):
        hit = next((x for x in techniques if x["id"] == t["id"]), None)
        if hit:
            hit.setdefault("mappingType", t.get("mappingType"))
            hit["via"] = (hit.get("via") + "; " if hit.get("via") else "") + "CTID KEV mapping"
        else:
            techniques.append(dict(t))
    order = {"exploitation_technique": 0, "primary_impact": 1, "secondary_impact": 2}
    techniques.sort(key=lambda t: (order.get(t.get("mappingType"), 3), t["id"]))

    ransomware = "known" if (kev or {}).get("ransomware") == "known" or (vc or {}).get("ransomware") == "Known" else None
    return {
        "exploitation": {"zeroDay": bool(p0), "inTheWild": bool(sources), "sources": sources},
        "zeroDay": p0,
        "pocs": pocs | {"count": poc_count},
        "intel": {"groups": att.get("groups", []), "campaigns": att.get("campaigns", []),
                  "software": att.get("software", []), "ransomware": ransomware,
                  "exploitationReports": (vc or {}).get("reports", [])},
        "attack": {"techniques": techniques[:20]},
    }


def exploited_set(src: dict) -> set[str]:
    out: set[str] = set()
    for k in ("p0", "euvd", "vulncheck"):
        out |= set((src.get(k) or {}).keys())
    return out
