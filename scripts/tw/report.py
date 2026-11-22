"""Daily Enterprise Cybersecurity Threat Intelligence Brief — the published document.

The brief page renders `brief["report"]`: a fixed seven-section document (plus primary
references) laid out like Aegis's reference brief of 2026-11-22.

  1. Executive Intelligence Summary         5. Threat Actor Intelligence
  2. Critical Vulnerability Intelligence    6. Enterprise Risk and Remediation Decisions
  3. Active Exploitation and Threat Campaigns  7. Significant Changes to Previously Reported Issues
  4. Industry and Market Threat Landscape   Primary Public References

Every section is generated automatically each morning from the feeds (CISA KEV, NVD, FIRST
EPSS, Google Project Zero, ENISA EUVD, VulnCheck KEV, Metasploit, Exploit-DB, PoC-in-GitHub,
MITRE ATT&CK / CTID). The wording is deliberately conservative: anything the feeds cannot
establish is stated as "not established" / "not verified", never guessed.

An analyst can replace any section for a given day with reviewed text by adding
threatwatch/data/editorial/<YYYY-MM-DD>.json → "report" (see safe_report_editorial).

Block model (rendered with textContent only; **double asterisks** mark bold runs):
  {"type": "p", "text": "..."}
  {"type": "table", "columns": ["A", "B"(, "C")], "rows": [["..", ".."], ...]}
"""
from __future__ import annotations

import html
import json
import re
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from .common import ET, iso, safe_url

REPORT_VERSION = 1
TITLE = ["DAILY ENTERPRISE CYBERSECURITY", "THREAT INTELLIGENCE BRIEF"]
FOOTER = "Enterprise Cyber Threat Intelligence"
SECTIONS = [
    ("summary", "Executive Intelligence Summary"),
    ("critical", "Critical Vulnerability Intelligence"),
    ("exploitation", "Active Exploitation and Threat Campaigns"),
    ("industry", "Industry and Market Threat Landscape"),
    ("actors", "Threat Actor Intelligence"),
    ("remediation", "Enterprise Risk and Remediation Decisions"),
    ("changes", "Significant Changes to Previously Reported Issues"),
]
SECTION_IDS = [s for s, _ in SECTIONS]
MAX_PRIORITIZED = 6          # CVEs given full write-ups in section 2
MAX_NEW_CRITICAL = 3         # newly published (not exploited) critical CVEs among them
TRACK_DAYS = 14              # how long a prioritized CVE is followed in section 7
MAX_CHANGES = 10
KEV_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
EPSS_PAGE = "https://www.first.org/epss/"
P0_PAGE = "https://docs.google.com/spreadsheets/d/1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY"

# ------------------------------------------------------------------ vocabulary
CWE_KIND = {
    "CWE-22": "path traversal", "CWE-23": "path traversal", "CWE-36": "path traversal",
    "CWE-73": "arbitrary file write", "CWE-434": "unrestricted file upload", "CWE-59": "link-following",
    "CWE-77": "command injection", "CWE-78": "OS command injection", "CWE-94": "code injection",
    "CWE-95": "code injection", "CWE-917": "expression-language injection", "CWE-1336": "template injection",
    "CWE-502": "unsafe deserialization", "CWE-89": "SQL injection", "CWE-79": "cross-site scripting",
    "CWE-918": "server-side request forgery", "CWE-611": "XML external entity",
    "CWE-287": "authentication bypass", "CWE-288": "authentication bypass", "CWE-290": "authentication bypass",
    "CWE-306": "missing authentication", "CWE-862": "missing authorization", "CWE-863": "incorrect authorization",
    "CWE-639": "authorization bypass", "CWE-798": "hard-coded credentials", "CWE-269": "privilege escalation",
    "CWE-284": "improper access control", "CWE-416": "use-after-free", "CWE-415": "double-free",
    "CWE-787": "out-of-bounds write", "CWE-125": "out-of-bounds read", "CWE-119": "memory corruption",
    "CWE-120": "buffer overflow", "CWE-121": "stack buffer overflow", "CWE-122": "heap buffer overflow",
    "CWE-190": "integer overflow", "CWE-476": "NULL pointer dereference", "CWE-843": "type confusion",
    "CWE-400": "resource exhaustion", "CWE-770": "resource exhaustion", "CWE-352": "cross-site request forgery",
    "CWE-200": "information disclosure", "CWE-601": "open redirect", "CWE-20": "input-validation",
}
TEXT_KIND = [  # description phrase -> (kind, CWE used for hunting guidance)
    (r"arbitrary file write|write arbitrary files", "arbitrary file write", "CWE-73"),
    (r"directory traversal|path traversal", "path traversal", "CWE-22"),
    (r"file upload", "unrestricted file upload", "CWE-434"),
    (r"os command injection|command injection", "command injection", "CWE-78"),
    (r"deserializ", "unsafe deserialization", "CWE-502"),
    (r"sql injection", "SQL injection", "CWE-89"),
    (r"server-side request forgery|\bssrf\b", "server-side request forgery", "CWE-918"),
    (r"authentication bypass|bypass authentication", "authentication bypass", "CWE-287"),
    (r"privilege escalation|escalate privileges", "privilege escalation", "CWE-269"),
    (r"use[- ]after[- ]free", "use-after-free", "CWE-416"),
    (r"double[- ]free", "double-free", "CWE-415"),
    (r"buffer overflow|out-of-bounds write", "memory corruption", "CWE-787"),
    (r"type confusion", "type confusion", "CWE-843"),
    (r"remote code execution|execute arbitrary code", "remote code execution", "CWE-94"),
    (r"cross-site scripting|\bxss\b", "cross-site scripting", "CWE-79"),
]
HUNT = [  # (CWE set, hunting guidance, short action phrase)
    ({"CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-434", "CWE-59"},
     "inspect unexpected file writes outside the application's data directories, new web-accessible files, "
     "modified application code, altered SSH authorized_keys files and suspicious scheduled jobs",
     "unexpected file writes and persistence"),
    ({"CWE-77", "CWE-78", "CWE-94", "CWE-95", "CWE-917", "CWE-1336", "CWE-502"},
     "inspect unexpected child processes of the service, new scheduled jobs or services, and unusual outbound "
     "connections from the host",
     "unexpected child processes and outbound connections"),
    ({"CWE-287", "CWE-288", "CWE-290", "CWE-306", "CWE-862", "CWE-863", "CWE-639", "CWE-798", "CWE-284", "CWE-269"},
     "review administrative logins, newly created accounts or API tokens, and configuration changes made "
     "without a matching change record",
     "unauthorized administrative access and configuration changes"),
    ({"CWE-416", "CWE-415", "CWE-787", "CWE-125", "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-190",
      "CWE-476", "CWE-843"},
     "investigate crashes, restarts or core dumps of the affected component associated with crafted input, "
     "while avoiding attribution based solely on a crash",
     "crashes tied to crafted input"),
    ({"CWE-918"}, "review outbound requests from the service to internal addresses or cloud metadata endpoints",
     "unexpected internal or metadata requests"),
    ({"CWE-89"}, "review database errors and anomalous queries originating from the application",
     "anomalous database queries"),
]
HUNT_DEFAULT = ("review the affected service's logs for unusual requests and changes around the disclosure date",
                "unusual requests and changes")

SECTOR_KEYWORDS = [
    ("Healthcare / medical imaging", ("medical", "health", "dicom", "pacs", "hl7", "fhir", "ehr", "monai",
                                      "imaging", "hospital", "patient", "clinic", "openemr", "orthanc")),
    ("Education / research", ("moodle", "canvas", "blackboard", "university", "education", "student", "research",
                              "jupyter", "notebook", "monai", "academic", "learning")),
    ("Technology / software", ()),
    ("Government / defense", ()),
    ("Financial services", ("bank", "payment", "finance", "trading", "swift", "atm", "pgp", "openpgp", "gpg")),
    ("Manufacturing / energy / utilities", ("scada", "plc", "hmi", "ics", "modbus", "siemens", "schneider",
                                            "rockwell", "abb", "honeywell", "mitsubishi", "omron", "ge vernova",
                                            "industrial", "energy", "solar", "inverter", "utility")),
    ("Retail / transportation", ("pos", "point of sale", "magento", "woocommerce", "commerce", "shop", "retail",
                                 "logistics", "fleet", "transport", "aviation", "rail")),
]

ATTACK_T1190 = {"id": "T1190", "name": "Exploit Public-Facing Application",
                "url": "https://attack.mitre.org/techniques/T1190/"}
MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
          "November", "December"]


# ------------------------------------------------------------------ small helpers
def _p(text: str) -> dict:
    return {"type": "p", "text": text}


def _table(columns: list[str], rows: list[list[str]]) -> dict:
    return {"type": "table", "columns": columns, "rows": rows}


def _long(d: date) -> str:
    return f"{MONTHS[d.month - 1]} {d.day}, {d.year}"


def _day_label(d: date) -> str:
    return f"{d.strftime('%A')}, {_long(d)}"


def _window_label(start: date, end: date) -> str:
    if start == end:
        return _long(end)
    if start.year == end.year and start.month == end.month:
        return f"{MONTHS[end.month - 1]} {start.day}-{end.day}, {end.year}"
    if start.year == end.year:
        return f"{MONTHS[start.month - 1]} {start.day} - {MONTHS[end.month - 1]} {end.day}, {end.year}"
    return f"{_long(start)} - {_long(end)}"


def _short_date(d: date) -> str:
    return f"{d.day} {MONTHS[d.month - 1][:3]} {d.year}"


def _d(s: str | None) -> date | None:
    try:
        return date.fromisoformat(str(s)[:10]) if s else None
    except ValueError:
        return None


def _et_date(ts: str | None) -> date | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(ET).date()
    except ValueError:
        return _d(ts)


def _join(items: list[str], conj: str = "and") -> str:
    items = [i for i in items if i]
    if len(items) <= 1:
        return "".join(items)
    if len(items) == 2:
        return f"{items[0]} {conj} {items[1]}"
    return ", ".join(items[:-1]) + f" {conj} " + items[-1]


ITW_TEXT = re.compile(r"exploited in the wild|actively exploited|being (?:actively )?exploited|exploited in attacks|"
                      r"exploitation in the wild|has been exploited", re.I)


def _clean_text(t: str | None) -> str:
    t = html.unescape(str(t or "")).replace("\ufffd", " ")
    t = re.sub(r"<[^>]{1,80}>", " ", t)
    return re.sub(r"\s+", " ", t).strip()


def _trim(t: str, n: int) -> str:
    """Cut at a sentence boundary when possible."""
    if len(t) <= n:
        return t
    cut = t[:n]
    end = max(cut.rfind(". "), cut.rfind("; "))
    return cut[:end + 1] if end > n * 0.5 else cut.rsplit(" ", 1)[0] + "…"


def _ord(n: int) -> str:
    return f"{n}{'th' if 10 <= n % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')}"


def _product_from_text(desc: str) -> str | None:
    m = re.search(r"\(aka ([^)]{2,40})\)", desc)
    if m:
        return m.group(1).strip()
    m = re.match(r"(?:The )?(.{3,70}?) (plugin|theme) for WordPress", desc)
    if m:
        return f"{m.group(1).strip()} WordPress {m.group(2)}"
    name = r"((?:[A-Z][\w\-]*)(?: [A-Z][\w\-]*){0,3})"
    m = re.search(r"\b(?:identified|found|discovered|exists|vulnerability|flaw|weakness) in (?:the )?" + name, desc)
    if m:
        return m.group(1).strip()
    m = re.match(name + r" (?:through|before|prior to|versions?|v?\d)", desc)
    if m:
        return m.group(1).strip()
    m = re.search(r"\bin ((?:[A-Z][\w\-]*)(?: (?:for )?[A-Z][\w\-]*){0,3}) (?:prior to|before|through|versions?|v?\d)", desc)
    return m.group(1).strip() if m else None


def _src(name: str) -> str:
    return re.sub(r"\s*\(exploited\)$", "", name)


def _n(n: int, one: str, many: str | None = None) -> str:
    return f"{n:,} {one if n == 1 else (many or one + 's')}"


# ------------------------------------------------------------------ per-CVE facts
class Item:
    """Facts about one CVE, derived from its catalog record (or the brief's KEV entry)."""

    def __init__(self, cid: str, rec: dict | None, brief_entry: dict | None, epss: tuple | None, reason: str):
        r = rec or {}
        b = brief_entry or {}
        self.cve, self.reason = cid, reason
        self.vendor = r.get("vendor") or b.get("vendor") or ""
        self.product = re.sub(r"\s*\(\+\d+ other products?\)$", "", r.get("product") or b.get("product") or "")
        if not self.vendor and not self.product:
            self.product = cid
        self.title = r.get("title") or b.get("name")
        self.description = _clean_text(r.get("description") or b.get("description"))
        if self.product == cid and self.description:
            guess = _product_from_text(self.description)
            if guess:
                self.vendor, self.product = "", guess
        self.text_itw = bool(ITW_TEXT.search(self.description))
        self.cvss = r.get("cvss") or b.get("cvss")
        self.cwes = r.get("cwes") or b.get("cwes") or []
        self.affected = r.get("affected") or []
        kev = r.get("kev") or b.get("kev")
        self.kev = kev
        ex = r.get("exploitation") or {}
        self.zero_day = bool(ex.get("zeroDay"))
        self.exploit_sources = [s for s in ex.get("sources") or [] if s.get("source") != "CISA KEV"]
        self.p0 = r.get("zeroDay") or None
        pocs = r.get("pocs") or {}
        self.pocs = pocs
        self.poc_count = int(pocs.get("count") or 0) if pocs else len(r.get("exploitRefs") or [])
        intel = r.get("intel") or {}
        self.groups = intel.get("groups") or []
        self.campaigns = intel.get("campaigns") or []
        self.ransomware = (kev or {}).get("ransomware") == "known" or intel.get("ransomware") == "known"
        self.techniques = (r.get("attack") or {}).get("techniques") or []
        self.fix_refs = r.get("fixRefs") or []
        self.vendor_refs = r.get("vendorRefs") or []
        self.nvd_status = r.get("nvdStatus") or b.get("nvdStatus")
        self.published = r.get("published")
        self.epss = epss or ((b.get("epss") or {}).get("score"), (b.get("epss") or {}).get("percentile")) \
            if (epss or b.get("epss")) else None
        if self.epss and self.epss[0] is None:
            self.epss = None
        self.priority = self._priority()

    # -- labels
    @property
    def label(self) -> str:
        v, p = self.vendor.strip(), self.product.strip()
        if v and p and (p.lower().startswith(v.lower()) or v.lower() in ("", "n/a")):
            return p
        return f"{v} {p}".strip() or self.cve

    @property
    def short(self) -> str:
        return self.product or self.label

    @property
    def kind(self) -> str:
        for c in self.cwes:
            if c in CWE_KIND and c != "CWE-20":
                return CWE_KIND[c]
        tk = self._text_kind()
        if tk:
            return tk[0]
        return CWE_KIND["CWE-20"] if "CWE-20" in self.cwes else ""

    def _text_kind(self) -> tuple[str, str] | None:
        for pat, kind, cwe in TEXT_KIND:
            if re.search(pat, self.description, re.I):
                return kind, cwe
        return None

    @property
    def score(self) -> float | None:
        return (self.cvss or {}).get("score")

    @property
    def network_unauth(self) -> bool:
        cv = self.cvss or {}
        return (cv.get("attackVector") or "").upper() == "NETWORK" and (cv.get("privileges") or "").upper() == "NONE"

    @property
    def network(self) -> bool:
        return ((self.cvss or {}).get("attackVector") or "").upper() in ("NETWORK", "ADJACENT_NETWORK", "ADJACENT")

    @property
    def exploited(self) -> bool:
        return bool(self.kev) or bool(self.exploit_sources) or self.zero_day or self.text_itw

    def _priority(self) -> str:
        s = self.score or 0
        if self.exploited and (self.network or self.cvss is None):
            return "Emergency"
        if self.exploited or (s >= 9.0 and self.network_unauth) or (self.poc_count and s >= 7.0):
            return "Urgent"
        return "Routine"

    # -- sentences
    def heading(self) -> str:
        kind = self.kind or (self.title or "vulnerability")
        sc = f" (CVSS {self.score:g})" if self.score is not None else ""
        return f"{self.cve} - {self.label} {kind}{sc}."

    def exploitation_phrase(self) -> str:
        parts = []
        if self.kev:
            parts.append(f"listed in CISA KEV on {self.kev.get('dateAdded')} (exploitation confirmed by CISA)")
        if self.zero_day:
            parts.append("tracked by Google Project Zero as exploited in the wild as a zero-day")
        for s in self.exploit_sources:
            if s["source"].startswith("Google Project Zero"):
                continue
            parts.append(f"reported exploited by {_src(s['source'])}" + (f" since {s['date']}" if s.get("date") else ""))
        if self.text_itw and not parts:
            parts.append("described in its CVE record as exploited in the wild (not yet corroborated by CISA KEV, "
                         "Project Zero, EUVD or VulnCheck)")
        return _join(parts) if parts else ""

    def poc_phrase(self) -> str:
        p = self.pocs or {}
        bits = []
        if p.get("metasploit"):
            bits.append(_n(len(p["metasploit"]), "Metasploit module"))
        if p.get("exploitdb"):
            bits.append(_n(len(p["exploitdb"]), "Exploit-DB entry", "Exploit-DB entries"))
        if p.get("vulncheckXdb"):
            bits.append(_n(len(p["vulncheckXdb"]), "VulnCheck XDB exploit"))
        if p.get("githubTotal"):
            bits.append(_n(p["githubTotal"], "unvetted GitHub repository", "unvetted GitHub repositories"))
        if p.get("nvdTagged") and not bits:
            bits.append(_n(len(p["nvdTagged"]), "NVD reference tagged Exploit", "NVD references tagged Exploit"))
        if not bits:
            return "No public exploit or proof-of-concept identified in tracked sources"
        weaponized = bool(p.get("metasploit") or p.get("vulncheckXdb"))
        return ("Public exploit code referenced: " + _join(bits)
                + ("" if weaponized else "; weaponized exploit not verified"))

    def affected_phrase(self) -> str:
        if not self.affected:
            return "Affected releases: not yet published in NVD configuration data."
        apps = [a for a in self.affected if a.get("part") != "o"] or self.affected
        shown = [f"{a['product'].replace('_', ' ')} {a['versions']}" for a in apps[:3]]
        more = len(apps) - len(shown)
        return "Affected releases (NVD): " + "; ".join(shown) + (f"; +{more} more" if more > 0 else "") + "."

    def fixed_versions(self) -> list[str]:
        out = []
        for a in self.affected:
            for part in str(a.get("versions") or "").split(","):
                part = part.strip()
                if part.startswith("< ") and not part.startswith("<= "):
                    v = f"{a['product'].replace('_', ' ')} {part[2:]}"
                    if v not in out:
                        out.append(v)
        return out[:4]

    def fixed_phrase(self) -> str:
        fixed = self.fixed_versions()
        if fixed:
            return "Fixed version (first unaffected release per NVD ranges): " + ", ".join(fixed) + "."
        if self.fix_refs or self.vendor_refs:
            n = len(self.fix_refs) or len(self.vendor_refs)
            return f"Fixed package release: not mapped in NVD ranges; {_n(n, 'vendor patch or advisory reference')} available."
        return "Fixed package release: none identified in tracked sources."

    def attack_path(self) -> str:
        cv = self.cvss or {}
        if not cv:
            return "Attack path: not established (no CVSS vector published yet)."
        av = {"NETWORK": "network-accessible", "ADJACENT_NETWORK": "adjacent-network", "ADJACENT": "adjacent-network",
              "LOCAL": "local access required", "PHYSICAL": "physical access required"}.get(
            (cv.get("attackVector") or "").upper(), "attack vector not established")
        pr = {"NONE": "no authentication required", "LOW": "low-privileged authentication required",
              "HIGH": "high-privileged authentication required"}.get((cv.get("privileges") or "").upper(),
                                                                       "privileges not established")
        ui = {"NONE": "no user interaction required", "REQUIRED": "user interaction required",
              "PASSIVE": "passive user interaction required", "ACTIVE": "active user interaction required"}.get(
            (cv.get("userInteraction") or "").upper(), "user interaction not established")
        return f"Attack path: {av}; {pr}; {ui}."

    def epss_phrase(self) -> str:
        if not self.epss:
            return "Not verified"
        return f"{self.epss[0] * 100:.1f}% probability / {_ord(min(99, int(self.epss[1] * 100)))} percentile (FIRST EPSS)"

    def kev_phrase(self) -> str:
        if self.kev:
            due = self.kev.get("dueDate")
            return (f"Listed {self.kev.get('dateAdded')}" + (f"; federal due date {due}" if due else "")
                    + ("; known ransomware use" if self.kev.get("ransomware") == "known" else ""))
        return "Not listed in latest verified baseline"

    def exploitation_status(self) -> str:
        ph = self.exploitation_phrase()
        if ph:
            return ph[0].upper() + ph[1:] + "; independently corroborated victim evidence not established"
        return "No malicious exploitation confirmed by tracked sources"

    def mitigation(self) -> str:
        if self.kev and self.kev.get("requiredAction"):
            ra = _clean_text(re.sub(r"\s*\(see URL in Notes\)", "", self.kev["requiredAction"]))
            return _trim(ra, 330)
        fixed = self.fixed_versions()
        steps = [f"Update to a fixed release ({', '.join(fixed[:2])})" if fixed else "Apply the vendor fix or mitigation"]
        if self.network:
            steps.append("remove untrusted network reachability until patched")
        if self.network_unauth:
            steps.append("place the service behind authentication or a VPN")
        steps.append("investigate for signs of prior compromise" if self.exploited else "monitor for exploitation")
        return "; ".join(steps)

    def hunting(self) -> tuple[str, str]:
        cw = set(self.cwes)
        tk = self._text_kind()
        if tk:
            cw.add(tk[1])
        for cset, text, short in HUNT:
            if cw & cset:
                return text, short
        return HUNT_DEFAULT

    def snapshot(self, edition: str, first: str | None = None) -> dict:
        return {"label": self.label, "firstReported": first or edition, "kev": bool(self.kev),
                "kevDate": (self.kev or {}).get("dateAdded"), "zeroDay": self.zero_day,
                "itw": sorted(s["source"] for s in self.exploit_sources), "poc": self.poc_count,
                "epss": self.epss[0] if self.epss else None, "cvss": self.score, "fix": bool(self.fixed_versions()
                                                                                            or self.fix_refs),
                "nvdStatus": self.nvd_status, "priority": self.priority}


# ------------------------------------------------------------------ selection
def select_items(brief: dict, catalog: "Catalog", tracked_before: set[str], now: datetime) -> list[Item]:
    """Newly prioritized CVEs for the edition, most important first."""
    edition = _d(brief["edition"])
    start = _et_date(brief["window"]["start"]) or (edition - timedelta(days=1))
    if start >= edition:
        start = edition - timedelta(days=1)
    chosen: dict[str, Item] = {}

    # A. new CISA KEV additions (always)
    for e in brief.get("cves") or []:
        chosen[e["cve"]] = Item(e["cve"], catalog.record(e["cve"]), e, catalog.epss(e["cve"]), "kev")

    # B. newly reported zero-day / in-the-wild exploitation (Project Zero, EUVD, VulnCheck, or a recently
    #    published CVE record that itself states exploitation in the wild). One extra day of look-back
    #    absorbs feed lag; tracking prevents repeats.
    look = start - timedelta(days=1)
    for row in catalog.rows():
        cid = row["cve"]
        if cid in chosen or cid in tracked_before:
            continue
        pub = _d(row.get("published"))
        recent = bool(pub and look <= pub <= edition)
        if not (row["zeroDay"] or row["itw"] or recent):
            continue
        rec = catalog.record(cid)
        if not rec:
            continue
        if not (row["zeroDay"] or row["itw"]):
            if ITW_TEXT.search(_clean_text(rec.get("description"))):
                chosen[cid] = Item(cid, rec, None, catalog.epss(cid), "itw")
            continue
        dates = [_d(s.get("date")) for s in (rec.get("exploitation") or {}).get("sources") or []
                 if s.get("source") != "CISA KEV"]
        z = rec.get("zeroDay") or {}
        dates += [_d(z.get("discovered")), _d(z.get("patched"))]
        if any(d and look <= d <= edition for d in dates) or (_d(rec.get("published")) or date.min) >= look:
            if (rec.get("kev") or {}).get("dateAdded") and _d(rec["kev"]["dateAdded"]) < start:
                continue  # long-known KEV entry, not new
            chosen[cid] = Item(cid, rec, None, catalog.epss(cid), "itw")

    # C. newly published critical CVEs, network-reachable, ranked by public exploit, EPSS, CVSS
    crit = []
    for row in catalog.rows():
        cid = row["cve"]
        pub = _d(row["published"])
        if cid in chosen or cid in tracked_before or not pub or not (start <= pub <= edition):
            continue
        if (row["cvss"] or 0) >= 9.0:
            crit.append(row)
    crit.sort(key=lambda r: (-(1 if r["poc"] else 0), -((catalog.epss(r["cve"]) or (0, 0))[0]),
                             -(r["cvss"] or 0), r["cve"]))
    added = 0
    for row in crit:
        if added >= MAX_NEW_CRITICAL:
            break
        it = Item(row["cve"], catalog.record(row["cve"]), None, catalog.epss(row["cve"]), "critical")
        if not it.network:
            continue
        chosen[row["cve"]] = it
        added += 1

    order = {"Emergency": 0, "Urgent": 1, "Routine": 2}
    items = sorted(chosen.values(), key=lambda i: (order[i.priority], 0 if i.exploited else 1, -(i.poc_count > 0),
                                                   -((i.epss or (0, 0))[0] or 0), -(i.score or 0), i.cve))
    return items


# ------------------------------------------------------------------ catalog access
class Catalog:
    def __init__(self, data_dir: Path):
        self.dir = data_dir / "cves"
        idx = _read(self.dir / "index.json") or {}
        fields = idx.get("fields") or []
        self._rows = [dict(zip(fields, r)) for r in idx.get("items") or []]
        ep = _read(self.dir / "epss.json") or {}
        self._epss = ep.get("scores") or {}
        self._cache: dict[str, dict | None] = {}

    def rows(self) -> list[dict]:
        return self._rows

    def record(self, cid: str) -> dict | None:
        if cid not in self._cache:
            self._cache[cid] = _read(self.dir / cid.split("-")[1] / f"{cid}.json")
        return self._cache[cid]

    def epss(self, cid: str) -> tuple | None:
        v = self._epss.get(cid)
        return (v[0], v[1]) if isinstance(v, list) and len(v) == 2 else None

    def kev_count(self) -> int | None:
        n = sum(1 for r in self._rows if r.get("kev"))
        return n or None

    def kev_latest(self) -> dict:
        """Fallback for briefs published before brief['kevLatest'] existed."""
        if not hasattr(self, "_kev_latest"):
            batch, last = [], ""
            for row in self._rows:
                if not row.get("kev"):
                    continue
                k = (self.record(row["cve"]) or {}).get("kev") or {}
                d = k.get("dateAdded") or ""
                if d > last:
                    last, batch = d, []
                if d == last:
                    batch.append((row, k))
            st = _read(self.dir / "status.json") or {}
            dues = sorted(k.get("dueDate") for _, k in batch if k.get("dueDate"))
            self._kev_latest = {"date": last or None, "dueDate": dues[0] if dues else None,
                                "catalogVersion": (st.get("sources") or {}).get("kevCatalogVersion"),
                                "items": [{"cve": r["cve"], "vendor": r["vendor"], "product": r["product"]}
                                          for r, _ in sorted(batch, key=lambda x: x[0]["cve"])[:12]]} if last else {}
        return self._kev_latest

    def high_critical_published(self, start: date, end: date) -> int:
        return sum(1 for r in self._rows if (r.get("severity") in ("HIGH", "CRITICAL"))
                   and (d := _d(r.get("published"))) and start <= d <= end)


def _read(p: Path) -> Any:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


# ------------------------------------------------------------------ compose
def compose(brief: dict, catalog: Catalog, track: dict, editorial: dict | None, now: datetime) -> tuple[dict, dict]:
    """Return (report, new_track_state). `track` = {"editions": {edition: {cve: snapshot}}}."""
    edition = brief["edition"]
    ed_date = _d(edition)
    editions = {e: v for e, v in (track.get("editions") or {}).items()
                if e < edition and _d(e) and (ed_date - _d(e)).days <= TRACK_DAYS}
    tracked: dict[str, dict] = {}
    for e in sorted(editions):  # latest snapshot per CVE; keep the earliest firstReported
        for cid, snap in editions[e].items():
            first = (tracked.get(cid) or {}).get("firstReported") or snap.get("firstReported") or e
            tracked[cid] = {**snap, "firstReported": first}

    items = select_items(brief, catalog, set(tracked), now)
    top = items[:MAX_PRIORITIZED]
    counts = brief["executive"]["counts"]
    w_start = _et_date(brief["window"]["start"]) or ed_date
    w_end = _et_date(brief["window"]["end"]) or ed_date
    if w_start > w_end:
        w_start = w_end
    if w_start == w_end:
        w_start = w_end - timedelta(days=1)

    gen = {
        "summary": _summary(brief, items, top, tracked, catalog, w_start, w_end),
        "critical": _critical(top, items),
        "exploitation": _exploitation(brief, top, catalog),
        "industry": _industry(top),
        "actors": _actors(top),
        "remediation": _remediation(top, tracked),
        "changes": _changes(tracked, catalog, brief),
    }
    ed = (editorial or {}).get("report") or {}
    ed_secs = ed.get("sections") or {}
    sections = []
    for (sid, title), num in zip(SECTIONS, range(1, 8)):
        blocks = ed_secs.get(sid) or gen[sid]
        sections.append({"id": sid, "num": num, "title": title, "source": "editorial" if ed_secs.get(sid) else "generated",
                         "blocks": blocks})
    refs = ed.get("references") or _references(top, brief)
    sources_used = ["CISA KEV", "NVD", "FIRST EPSS", "Google Project Zero", "ENISA EUVD", "Metasploit", "Exploit-DB",
                    "PoC-in-GitHub", "MITRE ATT&CK"]
    any_ed = any(s["source"] == "editorial" for s in sections)
    report = {
        "version": REPORT_VERSION,
        "title": TITLE,
        "dateLabel": _day_label(ed_date),
        "window": ed.get("window") or f"Reporting window: {_window_label(w_start, w_end)}",
        "prepared": ed.get("prepared") or ("Analyst-reviewed edition" if any_ed
                                           else "Automated edition, issued 7:00 AM ET"),
        "sourceNote": ed.get("sourceNote") or (
            "This brief is compiled automatically from public sources (" + ", ".join(sources_used) + "). "
            "Exploitation statuses reflect what those sources report; anything they do not establish is stated as "
            "not established or not verified." + (" Sections marked analyst-reviewed carry Aegis analyst text."
                                                  if any_ed else "")),
        "sections": sections,
        "references": refs,
        "footer": f"{FOOTER} | {_short_date(ed_date)}",
        "reviewedBy": (editorial or {}).get("reviewedBy") if any_ed or ed else None,
        "generatedAt": iso(now),
        "prioritized": [i.cve for i in items],
    }
    snaps = {i.cve: i.snapshot(edition, (tracked.get(i.cve) or {}).get("firstReported")) for i in items}
    # keep following previously reported issues with fresh snapshots
    for cid, old in tracked.items():
        if cid in snaps:
            continue
        rec = catalog.record(cid)
        if rec:
            it = Item(cid, rec, None, catalog.epss(cid), "tracked")
            snaps[cid] = it.snapshot(edition, old.get("firstReported"))
    keep = {e: v for e, v in (track.get("editions") or {}).items()
            if _d(e) and (ed_date - _d(e)).days <= TRACK_DAYS and e != edition}
    keep[edition] = snaps
    return report, {"editions": dict(sorted(keep.items()))}


# ------------------------------------------------------------------ sections
def _summary(brief, items, top, tracked, catalog, w_start, w_end) -> list[dict]:
    c = brief["executive"]["counts"]
    out = []
    if top:
        lead = top[0]
        sev = ((lead.cvss or {}).get("severity") or "").lower()
        desc = " ".join(x for x in (sev if sev in ("critical", "high") else "", lead.kind or "security") if x)
        s = (f"The leading newly prioritized issue is **{lead.cve} ({lead.label})**, "
             f"{'an' if desc[:1] in 'aeiou' else 'a'} {desc} flaw")
        ex = lead.exploitation_phrase()
        s += f"; it is {ex}." if ex else ". Malicious exploitation was not confirmed by tracked sources."
        fixed = lead.fixed_versions()
        s += (f" A fixed release is identified ({fixed[0]})." if fixed else
              " No fixed release is mapped in NVD data yet." if not lead.fix_refs else " A vendor fix reference is available.")
        if len(top) > 1:
            second = top[1]
            ex2 = second.exploitation_phrase()
            s += (f" **{second.cve} ({second.label})** is another important newly highlighted issue; "
                  + (f"it is {ex2}." if ex2 else "malicious exploitation was not confirmed."))
        out.append(_p(s))
    else:
        out.append(_p("No CVE met ThreatWatch prioritization criteria in this reporting window (new CISA KEV "
                      "additions, newly reported zero-day or in-the-wild exploitation, or newly published "
                      "network-reachable CVSS 9+ vulnerabilities). Previously reported issues are tracked in section 7."))
    zero = [i for i in items if i.zero_day or i.exploit_sources or i.text_itw]
    kev_total = c.get("kevTotal") if c.get("kevTotal") is not None else catalog.kev_count()
    kl = brief.get("kevLatest") or catalog.kev_latest()
    baseline = (f"{kev_total:,}" if isinstance(kev_total, int) else "Not verified") + (
        f" (catalog version {kl['catalogVersion']}" + (f", released {kl['released'][:10]}" if kl.get("released") else "")
        + ")" if kl.get("catalogVersion") else "")
    kev_new = [i for i in items if i.reason == "kev"]
    emergencies = [i for i in items if i.priority == "Emergency"]
    hc = catalog.high_critical_published(w_start, w_end)
    rows = [
        ["Newly prioritized CVEs", (f"{len(items)}: " + (", ".join(i.label for i in items[:6]) + f" and {len(items) - 6} more"
                                    if len(items) > 6 else _join([i.label for i in items]))) if items else "None"],
        ["Latest KEV baseline", baseline],
        ["New KEV additions", (", ".join(f"{i.cve} ({i.label})" for i in kev_new[:5]) + f" and {len(kev_new) - 5} more"
                               if len(kev_new) > 5 else _join([f"{i.cve} ({i.label})" for i in kev_new])) if kev_new
         else "None verified in reporting window"],
        ["Emergency candidates", (f"{len(emergencies)} newly highlighted: " + _join(
            [("exposed " if i.network else "") + i.label for i in emergencies[:4]])) if emergencies else "None newly highlighted"],
        ["Complete worldwide High/Critical count",
         f"Not established; {_n(hc, 'High/Critical CVE')} published to NVD in the window (NVD-scored only)"],
    ]
    if zero:
        rows.insert(3, ["New zero-day / in-the-wild reports", _join([f"{i.cve} ({i.label})" for i in zero[:4]])])
    out.append(_table(["Metric", "Assessment"], rows))
    out.append(_p("**Top five actions:** " + _top_actions(top, tracked)))
    return out


def _top_actions(top: list[Item], tracked: dict) -> str:
    acts = []
    room = 3 if any(tracked.values()) else 4
    for it in top:
        if len(acts) >= room:
            break
        fixed = it.fixed_versions()
        if it.priority == "Emergency" and it.network:
            acts.append(f"isolate or patch exposed {it.label} ({it.cve})")
        elif fixed:
            acts.append(f"update {it.label} to {fixed[0].split(' ')[-1]} or later ({it.cve})")
        else:
            acts.append(f"apply the vendor fix for {it.label} ({it.cve})")
    prev_kev = [s["label"] for s in tracked.values() if s.get("kev")][:4]
    if prev_kev:
        acts.append(f"close previously reported {_join(prev_kev)} KEV exposure")
    prev_other = [f"{s['label']} {cid}" for cid, s in tracked.items() if not s.get("kev")][:2]
    if prev_other and len(acts) < 4:
        acts.append(f"validate remediation of {_join(prev_other)}")
    if top:
        acts.append(f"examine {top[0].label} hosts for {top[0].hunting()[1]}")
    if not acts:
        acts = ["confirm remediation of CISA KEV entries in scope for your environment",
                "review EPSS movers for internet-facing assets"]
    acts = acts[:5]
    acts = [a[0].upper() + a[1:] if i == 0 else a for i, a in enumerate(acts)]
    return "; ".join(f"({n}) {a}" for n, a in enumerate(acts, 1)) + "."


def _critical(top: list[Item], items: list[Item]) -> list[dict]:
    if not top:
        return [_p("No newly prioritized critical vulnerabilities in this reporting window.")]
    out = []
    for n, it in enumerate(top):
        desc = _trim(it.description, 420).rstrip(".")
        body = " ".join(x for x in (desc + ("" if desc.endswith("…") else ".") if desc else "", it.affected_phrase(), it.fixed_phrase(),
                                     it.attack_path()) if x)
        out.append(_p(f"**{it.heading()}** {body}"))
        if n == 0 or it.priority == "Emergency":
            out.append(_table(["Field", "Status"], [
                ["EPSS / percentile", it.epss_phrase()],
                ["CISA KEV", it.kev_phrase()],
                ["Exploitation", it.exploitation_status()],
                ["Public exploit", it.poc_phrase()],
                ["Mitigation", it.mitigation()],
            ]))
        else:
            out.append(_p(f"EPSS: {it.epss_phrase()}. CISA KEV: {it.kev_phrase()}. Exploitation: "
                          f"{it.exploitation_status()}. {it.poc_phrase()}. Mitigation: {it.mitigation()}."))
    if len(items) > len(top):
        rest = items[len(top):]
        out.append(_p("Also prioritized: " + "; ".join(f"{i.cve} ({i.label}, {i.priority.lower()})" for i in rest[:12])
                      + ". Details are in the Vulnerability Validation catalog."))
    return out


def _exploitation(brief: dict, top: list[Item], catalog: Catalog) -> list[dict]:
    out = []
    exploited = [i for i in top if i.exploit_sources or i.zero_day]
    if exploited:
        parts = []
        for i in exploited:
            actor = (" ATT&CK links " + _join([f"{g['name']} ({g['id']})" for g in (i.groups + i.campaigns)[:3]]) + "."
                     if (i.groups or i.campaigns) else
                     " No named actor, verified victim count or campaign is established in tracked sources.")
            parts.append(f"{i.cve} ({i.label}): {i.exploitation_phrase()}.{actor}")
        out.append(_p(" ".join(parts) + " No campaign-specific IP addresses, hashes or domains are collected by "
                      "ThreatWatch's automated feeds."))
    else:
        out.append(_p("No new zero-day or in-the-wild exploitation reports beyond CISA KEV were identified for newly "
                      "prioritized CVEs in tracked sources (Google Project Zero, ENISA EUVD, VulnCheck KEV). "
                      "No reliable campaign-specific IP addresses, hashes or domains were identified."))
    kl = brief.get("kevLatest") or catalog.kev_latest()
    new_kev = brief.get("cves") or []
    fed = (" This deadline applies to covered federal agencies under applicable requirements; it is not a "
           "universal private-sector mandate.")
    if new_kev:
        due = sorted({c["kev"]["dueDate"] for c in new_kev if c["kev"].get("dueDate")})
        names = _join([f"{c['vendor']} {c['product']}" for c in new_kev[:6]])
        s = (f"CISA added {_n(len(new_kev), 'vulnerability', 'vulnerabilities')} to the KEV catalog in the "
             f"reporting window: {names}{' and others' if len(new_kev) > 6 else ''}.")
        if due:
            s += f" The federal remediation deadline is **{_long(_d(due[0]))}**" + (
                f" (latest {_long(_d(due[-1]))})" if len(due) > 1 else "") + "." + fed
        rans = [c for c in new_kev if c["kev"].get("ransomware") == "known"]
        if rans:
            s += f" CISA flags known ransomware use for {_join([c['cve'] for c in rans])}."
        out.append(_p(s))
    elif kl.get("date"):
        names = _join([f"{x['vendor']} {x['product']}" for x in kl.get("items", [])[:6]])
        s = (f"No new CISA KEV additions were verified in the reporting window. The latest additions remain the "
             f"{_n(len(kl.get('items', [])), 'entry', 'entries')} added {_long(_d(kl['date']))}: {names}.")
        if kl.get("dueDate"):
            s += f" The federal remediation deadline for those entries is **{_long(_d(kl['dueDate']))}**." + fed
        out.append(_p(s))
    for ch in brief.get("changes") or []:
        if ch.get("type") == "ransomware_flag":
            out.append(_p(f"{ch['cve']}: {ch['detail']}"))
    hunts = []
    for i in top[:4]:
        text, _ = i.hunting()
        hunts.append(f"for {i.label} ({i.cve}), {text}")
    if hunts:
        out.append(_p("**Defensive hunting:** " + "; ".join(hunts) + "."))
    return out


def _industry(top: list[Item]) -> list[dict]:
    rows = []
    server = [i for i in top if i.network]
    for sector, words in SECTOR_KEYWORDS:
        hits = [i for i in top if words and any(re.search(r"\b" + re.escape(w) + r"\b",
                                                          f"{i.vendor} {i.product} {i.description}".lower())
                                                for w in words)]
        if hits:
            names = _join(sorted({i.label for i in hits}))
            text = f"{names} relevant to this sector; confirmed sector targeting not established"
        elif sector.startswith("Technology"):
            text = (f"Potential {_join(sorted({i.label for i in top})[:4])} dependency exposure" if top
                    else "No newly prioritized product exposure")
        elif server:
            pool = _join(sorted({i.label for i in server})[:3])
            text = (f"Possible {pool} exposure; no new sector-specific targeting confirmed" if sector.startswith("Gov")
                    else f"Possible {pool} exposure; targeting unknown")
        else:
            text = "No newly prioritized exposure identified; targeting unknown"
        rows.append([sector, text])
    return [_table(["Industry / market", "Observed activity vs. possible exposure"], rows),
            _p("Geography and organization-size targeting were not reliably established. Product use indicates "
               "possible exposure, not observed attacker selection.")]


def _actors(top: list[Item]) -> list[dict]:
    rows = []
    for i in top:
        if i.groups or i.campaigns:
            links = _join([f"{g['name']} ({g['id']})" for g in i.groups[:3]]
                          + [f"campaign {c['name']} ({c['id']})" for c in i.campaigns[:2]])
            rows.append([f"{i.label} operators", f"MITRE ATT&CK links {links} to {i.cve}; attribution follows "
                                                  "ATT&CK's cited reporting, not independent confirmation."])
        elif i.exploited:
            rows.append([f"{i.label} operators", "Unknown. Exploitation reported; identity, motivation and "
                                                  "geographic targeting not established."])
        else:
            rows.append([f"{i.label} operators", "No confirmed malicious exploitation or attribution."])
    if not rows:
        rows.append(["Newly prioritized CVEs", "None in this reporting window."])
    mapped, maybe = [], []
    for i in top:
        tech = [t for t in i.techniques if t.get("mappingType") in (None, "exploitation_technique")][:2]
        if tech:
            mapped.append(_join([f"{t['id']} ({t['name']})" for t in tech]) + f" is mapped for {i.cve}"
                          + (" via CTID" if any("CTID" in str(t.get("via")) for t in tech) else ""))
        elif i.network:
            maybe.append(i.label)
    note = []
    if mapped:
        note.append("; ".join(mapped) + ".")
    if maybe:
        note.append(f"{ATTACK_T1190['id']} ({ATTACK_T1190['name']}) may be relevant to exposed {_join(maybe[:4])} services.")
    if not note:
        note.append("No ATT&CK technique mappings apply to today's newly prioritized CVEs.")
    note.append("These mappings support defensive detection and do not establish actor attribution.")
    return [_table(["Actor / cluster", "Attribution and activity"], rows),
            _p("**MITRE ATT&CK defensive mapping:** " + " ".join(note))]


def _remediation(top: list[Item], tracked: dict) -> list[dict]:
    rows = []
    for i in top:
        if i.priority != "Emergency":
            continue
        scen = (f"{i.label} " + (f"({i.cve}) " if i.cve not in i.label else "")
                + ("reachable from untrusted networks" if i.network else "on exposed hosts"))
        rows.append(["Emergency", scen, "Isolate immediately; investigate and mitigate within 24 hours"])
    prev_kev = [s["label"] for s in tracked.values() if s.get("kev")]
    if prev_kev:
        rows.append(["Emergency", f"Unremediated confirmed-exploited {_join(sorted(set(prev_kev))[:5], 'or')} exposure",
                     "Immediate containment and applicable forensic triage"])
    for i in top:
        if i.priority != "Urgent":
            continue
        fixed = i.fixed_versions()
        rows.append(["Urgent", f"Vulnerable {i.label} ({i.cve})",
                     (f"Update to {fixed[0].split(' ')[-1]} in 24-72 hours" if fixed
                      else "Apply applicable vendor fix in 24-72 hours")])
    rows.append(["Routine", "Affected but effectively restricted software", "Controlled maintenance window"])
    rows.append(["Monitor", "Verified fixed or nonaffected software", "Watch for material new evidence"])
    return [_table(["Priority", "Scenario", "Suggested window"], rows),
            _p("Response windows are recommendations, not mandatory policy. No organization-specific exposure, "
               "compromise, asset criticality or patch status was established.")]


def _changes(tracked: dict, catalog: Catalog, brief: dict) -> list[dict]:
    rows = []
    for cid, old in sorted(tracked.items(), key=lambda kv: kv[1].get("firstReported") or "", reverse=True):
        rec = catalog.record(cid)
        if not rec:
            continue
        it = Item(cid, rec, None, catalog.epss(cid), "tracked")
        now = it.snapshot(brief["edition"])
        dev = []
        if now["kev"] and not old.get("kev"):
            dev.append(f"added to CISA KEV on {now['kevDate']}")
        if now["zeroDay"] and not old.get("zeroDay"):
            dev.append("now tracked by Google Project Zero as an in-the-wild zero-day")
        new_itw = sorted(set(now["itw"]) - set(old.get("itw") or []))
        if new_itw:
            dev.append("exploitation now reported by " + _join([_src(x) for x in new_itw]))
        if now["poc"] and not old.get("poc"):
            dev.append("public exploit code now referenced")
        elif now["poc"] > (old.get("poc") or 0) + 2:
            dev.append(f"public exploit references rose to {now['poc']}")
        if now["cvss"] is not None and old.get("cvss") is None:
            dev.append(f"NVD scored it CVSS {now['cvss']:g}")
        if now["fix"] and not old.get("fix"):
            dev.append("fixed-version or patch reference added")
        oe, ne = old.get("epss"), now["epss"]
        if oe is not None and ne is not None and abs(ne - oe) >= 0.10:
            dev.append(f"EPSS {'rose' if ne > oe else 'fell'} from {oe:.2f} to {ne:.2f}")
        first = _d(old.get("firstReported"))
        text = ("; ".join(dev)[0].upper() + "; ".join(dev)[1:]) if dev else (
            f"No significant new development established since {MONTHS[first.month - 1]} {first.day}" if first
            else "No significant new development established")
        rows.append([f"{it.label} {cid}", text])
        if len(rows) >= MAX_CHANGES:
            break
    for ch in brief.get("changes") or []:
        if ch.get("type") == "epss_change" and len(rows) < MAX_CHANGES and not any(ch["cve"] in r[0] for r in rows):
            rows.append([ch["cve"], ch["detail"]])
    if not rows:
        rows.append(["Previously reported issues", "None tracked in the last 14 days"])
    return [_table(["Issue", "Material development"], rows)]


def _references(top: list[Item], brief: dict) -> list[dict]:
    refs: list[dict] = []

    def add(label: str, url: str | None):
        u = safe_url(url)
        if u and all(r["url"] != u for r in refs):
            refs.append({"label": label, "url": u})

    for i in top:
        for r in (i.vendor_refs or i.fix_refs)[:1]:
            add(f"{i.label} vendor advisory", r["url"])
        add(f"{i.cve} NVD record", f"https://nvd.nist.gov/vuln/detail/{i.cve}")
        if i.p0:
            add(f"{i.label} Project Zero analysis", i.p0.get("rcaUrl") or i.p0.get("analysisUrl") or i.p0.get("advisoryUrl"))
        for c in i.campaigns[:1]:
            add(f"MITRE ATT&CK campaign {c['name']}", c.get("url"))
    add("CISA KEV catalog", KEV_PAGE)
    add("FIRST EPSS", EPSS_PAGE)
    if any(i.zero_day for i in top):
        add("Google Project Zero 0day In the Wild tracker", P0_PAGE)
    return refs[:16]


# ------------------------------------------------------------------ editorial + validation
def _check_blocks(blocks: Any, where: str) -> list[dict]:
    if not isinstance(blocks, list) or not blocks:
        raise ValueError(f"editorial report {where}: must be a non-empty list of blocks")
    out = []
    for b in blocks:
        if not isinstance(b, dict):
            raise ValueError(f"editorial report {where}: block is not an object")
        if b.get("type") == "p" and isinstance(b.get("text"), str) and b["text"].strip():
            out.append(_p(b["text"].strip()[:5000]))
        elif b.get("type") == "table":
            cols = b.get("columns")
            rows = b.get("rows")
            if not (isinstance(cols, list) and 2 <= len(cols) <= 4 and all(isinstance(c, str) for c in cols)):
                raise ValueError(f"editorial report {where}: table needs 2-4 string columns")
            if not isinstance(rows, list) or not rows or not all(
                    isinstance(r, list) and len(r) == len(cols) and all(isinstance(x, str) for x in r) for r in rows):
                raise ValueError(f"editorial report {where}: every table row needs {len(cols)} string cells")
            out.append(_table(cols, rows))
        else:
            raise ValueError(f"editorial report {where}: unknown block {b.get('type')!r}")
    return out


def safe_report_editorial(raw: Any, section_ids: list[str] | None = None) -> dict | None:
    """Validate editorial['report']: {window?, prepared?, sourceNote?, sections{id: blocks}, references[]}."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("editorial report must be an object")
    out: dict = {}
    for k in ("window", "prepared", "sourceNote"):
        if raw.get(k) is not None:
            if not isinstance(raw[k], str):
                raise ValueError(f"editorial report {k} must be text")
            out[k] = raw[k].strip()[:600]
    secs = raw.get("sections") or {}
    if not isinstance(secs, dict):
        raise ValueError("editorial report sections must be an object")
    allowed = section_ids or SECTION_IDS
    bad = set(secs) - set(allowed)
    if bad:
        raise ValueError(f"editorial report: unknown sections {sorted(bad)}; use {allowed}")
    out["sections"] = {k: _check_blocks(v, k) for k, v in secs.items()}
    if raw.get("references") is not None:
        refs = []
        for r in raw["references"]:
            u = safe_url((r or {}).get("url"))
            if not u or not str(r.get("label") or "").strip():
                raise ValueError(f"editorial report reference needs a label and an https URL: {r!r}")
            refs.append({"label": str(r["label"]).strip()[:200], "url": u})
        out["references"] = refs
    return out


def validate_report(rep: Any, section_ids: list[str] | None = None) -> list[str]:
    errs: list[str] = []
    if not isinstance(rep, dict):
        return ["report is not an object"]
    for k in ("title", "dateLabel", "window", "sourceNote", "sections", "references", "footer"):
        if k not in rep:
            errs.append(f"report missing {k}")
    if errs:
        return errs
    ids = [s.get("id") for s in rep["sections"]]
    if ids != (section_ids or SECTION_IDS):
        errs.append(f"report sections out of order: {ids}")
    for s in rep["sections"]:
        try:
            _check_blocks(s.get("blocks"), s.get("id"))
        except ValueError as exc:
            errs.append(str(exc))
    for r in rep["references"]:
        if not safe_url(r.get("url")):
            errs.append(f"report reference not https: {r.get('url')!r}")
    return errs





# ====================================================================== monthly summary
M_TITLE = ["MONTHLY ENTERPRISE CYBERSECURITY", "THREAT INTELLIGENCE SUMMARY"]
M_SECTIONS = [
    ("summary", "Executive Intelligence Summary"),
    ("critical", "Most Significant Vulnerabilities"),
    ("exploitation", "Exploitation and Zero-Day Activity"),
    ("industry", "Vendor and Industry Concentration"),
    ("actors", "Threat Actor Intelligence"),
    ("remediation", "Enterprise Risk and Remediation Decisions"),
    ("chronology", "Monthly Chronology"),
]
M_SECTION_IDS = [s for s, _ in M_SECTIONS]


def _month_bounds(month: str) -> tuple[date, date]:
    y, m = map(int, month.split("-"))
    first = date(y, m, 1)
    last = date(y + (m == 12), m % 12 + 1, 1) - timedelta(days=1)
    return first, last


def compose_month(doc: dict, catalog: Catalog, editorial: dict | None, now: datetime) -> dict:
    """Seven-section monthly summary from the month's KEV events plus catalog intel."""
    month = doc["month"]
    first, last = _month_bounds(month)
    today = now.astimezone(ET).date()
    end = min(last, today)
    mname = f"{MONTHS[first.month - 1]} {first.year}"
    metrics = {m["id"]: m["value"] for m in doc.get("metrics") or []}

    # month's KEV additions as Items
    items: list[Item] = []
    for e in doc.get("events") or []:
        entry = {"vendor": e.get("vendor"), "product": e.get("product"), "name": e.get("concern"),
                 "kev": {"dateAdded": e.get("date"), "ransomware": e.get("ransomware")}}
        items.append(Item(e["cve"], catalog.record(e["cve"]), entry, catalog.epss(e["cve"]), "kev"))
    kev_ids = {i.cve for i in items}

    # exploited / zero-day reports outside KEV whose report date falls in the month
    outside: list[tuple[date, Item]] = []
    for row in catalog.rows():
        if row["cve"] in kev_ids or not (row.get("zeroDay") or row.get("itw")):
            continue
        rec = catalog.record(row["cve"])
        if not rec or rec.get("kev"):
            continue
        dates = [_d(x.get("date")) for x in (rec.get("exploitation") or {}).get("sources") or []]
        z = rec.get("zeroDay") or {}
        dates += [_d(z.get("discovered")), _d(z.get("patched"))]
        hit = sorted(d for d in dates if d and first <= d <= end)
        if hit:
            outside.append((hit[0], Item(row["cve"], rec, None, catalog.epss(row["cve"]), "itw")))
    outside.sort(key=lambda x: (x[0], x[1].cve))

    def risk(i: Item):
        return (-((i.epss or (0, 0))[0] or 0), -(i.score or 0), i.cve)

    ranked = sorted(items, key=risk)
    in_window = first >= today - timedelta(days=90)
    published = [r for r in catalog.rows() if (d := _d(r.get("published"))) and first <= d <= end]
    hc = sum(1 for r in published if r.get("severity") in ("HIGH", "CRITICAL"))
    with_poc = sum(1 for i in items if i.poc_count)

    gen: dict[str, list] = {}
    # 1 summary
    lead = ranked[:2]
    s = (f"CISA added **{_n(len(items), 'vulnerability', 'vulnerabilities')}** to the KEV catalog in {mname}"
         + ("" if doc.get("complete") else f" (month to date through {_long(end)})")
         + f", spanning {_n(metrics.get('vendors', len({i.vendor for i in items})), 'vendor')}.")
    if metrics.get("ransomware"):
        s += f" CISA flags known ransomware use for {_n(metrics['ransomware'], 'of them', 'of them')}."
    if lead:
        s += " The highest-likelihood additions by EPSS were " + _join(
            [f"**{i.cve} ({i.label})**" for i in lead]) + "."
    if outside:
        s += (f" Outside KEV, {_n(len(outside), 'further CVE')} {'was' if len(outside) == 1 else 'were'} reported "
              "exploited or tracked as zero-days by Google Project Zero, ENISA EUVD or VulnCheck.")
    if not items and not outside:
        s = f"No CISA KEV additions or other exploited-vulnerability reports were recorded for {mname} yet."
    rows = [
        ["New KEV entries", f"{len(items):,}"],
        ["Distinct vendors", f"{metrics.get('vendors', 0):,}"],
        ["Known ransomware use", f"{metrics.get('ransomware', 0):,}"],
        ["EPSS ≥ 90th percentile", f"{metrics.get('epss90', 0):,} of the month's KEV entries"],
        ["Exploited or zero-day outside KEV", f"{len(outside):,} (Project Zero, ENISA EUVD, VulnCheck)"],
        ["Public exploit code referenced", f"{with_poc:,} of the month's KEV entries"],
        ["CVEs published to NVD", (f"{len(published):,} ({hc:,} High/Critical)" if in_window
                                   else "Not retained (catalog keeps the last 90 days)")],
    ]
    gen["summary"] = [_p(s), _table(["Metric", "Value"], rows),
                      _p(doc.get("notice") or "These are catalog counts, not a count of total cyber incidents."),
                      _p("**Top five actions:** " + _top_actions([i for i in ranked if i.network][:4] or ranked[:4], {}))]

    # 2 most significant
    sig = (ranked[:8] + [i for _, i in outside[:4]])[:10]
    if sig:
        trows = []
        for i in sig:
            status = []
            status.append("CISA KEV " + (i.kev or {}).get("dateAdded", "") if i.kev else "")
            if i.zero_day:
                status.append("Project Zero zero-day")
            status += [_src(x["source"]) for x in i.exploit_sources if not x["source"].startswith("Google")][:1]
            status.append(f"EPSS {_ord(min(99, int(i.epss[1] * 100)))} pct" if i.epss else "EPSS not verified")
            status.append("public exploit" if i.poc_count else "no public exploit identified")
            trows.append([i.cve, i.label, (i.kind or "vulnerability"), "; ".join(x for x in status if x)])
        blocks = [_table(["CVE", "Product", "Issue", "Status"], trows)]
        for i in sig[:3]:
            blocks.append(_p(f"**{i.heading()}** {_trim(i.description, 360)} {i.fixed_phrase()} {i.attack_path()}"))
        gen["critical"] = blocks
    else:
        gen["critical"] = [_p(f"No exploited vulnerabilities were recorded for {mname} yet.")]

    # 3 exploitation
    blocks = []
    weeks: dict[date, int] = {}
    for i in items:
        d = _d((i.kev or {}).get("dateAdded"))
        if d:
            wk = d - timedelta(days=d.weekday())
            weeks[wk] = weeks.get(wk, 0) + 1
    if weeks:
        blocks.append(_p("KEV additions by week: " + "; ".join(
            f"week of {MONTHS[w.month - 1][:3]} {w.day}: {n}" for w, n in sorted(weeks.items())) + "."))
    rans = [i for i in items if (i.kev or {}).get("ransomware") == "known"]
    if rans:
        blocks.append(_p("Known ransomware use (CISA): " + _join([f"{i.cve} ({i.label})" for i in rans]) + "."))
    if outside:
        blocks.append(_table(["Date", "CVE", "Report"], [
            [d.isoformat(), f"{i.cve} ({i.label})", _join([_src(x["source"]) for x in i.exploit_sources] or
                                                          ["Google Project Zero"]) +
             ("; zero-day" if i.zero_day else "")] for d, i in outside[:15]]))
    blocks.append(_p("No campaign-specific IP addresses, hashes or domains are collected by ThreatWatch's automated "
                     "feeds. Victim counts and campaign scope are not established unless cited in section 5."))
    kinds: dict[str, int] = {}
    for i in items + [i for _, i in outside]:
        k = i.hunting()[1]
        kinds[k] = kinds.get(k, 0) + 1
    if kinds:
        top_k = sorted(kinds.items(), key=lambda kv: -kv[1])[:3]
        blocks.append(_p("**Defensive hunting focus:** " + "; ".join(f"{k} ({n} CVEs)" for k, n in top_k) + "."))
    gen["exploitation"] = blocks

    # 4 vendor + industry
    vend: dict[str, list[Item]] = {}
    for i in items:
        vend.setdefault(i.vendor or i.label, []).append(i)
    vrows = [[v, str(len(lst)), _join(sorted({i.product for i in lst})[:4])]
             for v, lst in sorted(vend.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:10]]
    gen["industry"] = ([_table(["Vendor", "KEV entries", "Products"], vrows)] if vrows else []) + \
        _industry(ranked[:8] + [i for _, i in outside[:4]])

    # 5 actors
    linked = [i for i in items + [i for _, i in outside] if i.groups or i.campaigns]
    arows = [[f"{i.label} ({i.cve})", "MITRE ATT&CK links " + _join(
        [f"{g['name']} ({g['id']})" for g in i.groups[:3]] + [f"campaign {c['name']}" for c in i.campaigns[:2]])]
        for i in linked[:10]]
    unlinked = len(items) + len(outside) - len(linked)
    if unlinked:
        arows.append([f"Remaining {_n(unlinked, 'exploited CVE')}", "Unknown; identity, motivation and geographic "
                                                                    "targeting not established in tracked sources."])
    tech: dict[str, list] = {}
    for i in items:
        for t in i.techniques:
            tech.setdefault(f"{t['id']} ({t['name']})", []).append(i.cve)
    note = ("; ".join(f"{k} mapped for {_n(len(v), 'CVE')}" for k, v in
                      sorted(tech.items(), key=lambda kv: -len(kv[1]))[:5]) + ".") if tech else \
        "No ATT&CK technique mappings published yet for this month's CVEs."
    gen["actors"] = [_table(["Actor / cluster", "Attribution and activity"], arows or [["None", "No exploited CVEs recorded."]]),
                     _p("**MITRE ATT&CK defensive mapping:** " + note +
                        " These mappings support defensive detection and do not establish actor attribution.")]

    # 6 remediation
    net = sorted({i.label for i in items if i.network})
    other = sorted({i.label for i in items if not i.network})
    prow = []
    if net:
        prow.append(["Emergency", f"Unremediated internet-facing {_join(net[:6])}{' and others' if len(net) > 6 else ''}",
                     "Immediate containment and applicable forensic triage"])
    if outside:
        prow.append(["Urgent", "Products with exploitation reported outside KEV: " + _join(sorted({i.label for _, i in outside})[:5]),
                     "Apply vendor fixes in 24-72 hours"])
    if other:
        prow.append(["Urgent", f"Local or client-side KEV entries: {_join(other[:5])}", "Patch within 7 days"])
    prow += [["Routine", "Affected but effectively restricted software", "Controlled maintenance window"],
             ["Monitor", "Verified fixed or nonaffected software", "Watch for material new evidence"]]
    due = sorted((i for i in items if (i.kev or {}).get("dueDate")), key=lambda i: (i.kev["dueDate"], i.cve))
    # Item only sees dueDate when the catalog record carries it
    blocks = [_table(["Priority", "Scenario", "Suggested window"], prow)]
    up = [i for i in due if _d(i.kev["dueDate"]) and _d(i.kev["dueDate"]) >= today]
    if up:
        blocks.append(_table(["Federal due date", "CVE", "Product"],
                             [[_long(_d(i.kev["dueDate"])), i.cve, i.label] for i in up[:12]]))
    blocks.append(_p("Federal due dates apply to covered agencies under applicable requirements; they are not a "
                     "universal private-sector mandate. Response windows are recommendations, not mandatory policy."))
    gen["remediation"] = blocks

    # 7 chronology
    crow = []
    for e in doc.get("events") or []:
        dev = e.get("concern") or ""
        if e.get("ransomware") == "known":
            dev += "; known ransomware use"
        crow.append([e["date"], e["cve"], dev])
    for d, i in outside:
        crow.append([d.isoformat(), i.cve, f"{i.label}: exploitation reported by " +
                     _join([_src(x["source"]) for x in i.exploit_sources] or ["Google Project Zero"])])
    crow.sort(key=lambda r: (r[0], r[1]))
    gen["chronology"] = [_table(["Date", "CVE", "Development"], crow)] if crow else \
        [_p("No exploitation events recorded for this month yet.")]

    ed = (editorial or {}).get("report") or {}
    ed_secs = ed.get("sections") or {}
    sections = [{"id": sid, "num": n, "title": title, "source": "editorial" if ed_secs.get(sid) else "generated",
                 "blocks": ed_secs.get(sid) or gen[sid]} for n, (sid, title) in enumerate(M_SECTIONS, 1)]
    refs: list[dict] = []
    for i in ranked[:6]:
        for rf in (i.vendor_refs or i.fix_refs)[:1]:
            u = safe_url(rf.get("url"))
            if u and all(x["url"] != u for x in refs):
                refs.append({"label": f"{i.label} vendor advisory", "url": u})
    refs += [{"label": "CISA KEV catalog", "url": KEV_PAGE}, {"label": "FIRST EPSS", "url": EPSS_PAGE}]
    if outside:
        refs.append({"label": "Google Project Zero 0day In the Wild tracker", "url": P0_PAGE})
    any_ed = any(x["source"] == "editorial" for x in sections)
    period = _window_label(first, end)
    return {
        "version": REPORT_VERSION,
        "kind": "monthly",
        "title": M_TITLE,
        "dateLabel": mname,
        "window": ed.get("window") or f"Reporting period: {period}" + ("" if doc.get("complete") else " (month to date)"),
        "prepared": ed.get("prepared") or ("Analyst-reviewed summary" if any_ed else
                                           ("Final monthly summary" if doc.get("complete")
                                            else "Automated summary, refreshed daily at 7:00 AM ET")),
        "sourceNote": ed.get("sourceNote") or (
            "Compiled automatically from CISA KEV, NVD, FIRST EPSS, Google Project Zero, ENISA EUVD, VulnCheck, "
            "Metasploit, Exploit-DB, PoC-in-GitHub and MITRE ATT&CK. Counts are catalog counts, not a count of "
            "cyber incidents; anything the sources do not establish is stated as not established."),
        "sections": sections,
        "references": ed.get("references") or refs,
        "footer": f"{FOOTER} | {mname}",
        "generatedAt": iso(now),
    }


__all__ = ["compose", "compose_month", "Catalog", "safe_report_editorial", "validate_report", "SECTION_IDS",
           "M_SECTION_IDS"]
