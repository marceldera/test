"""Detection metadata: public Nuclei template index + Aegis-curated reviews.

A template's existence is a *reference*, never proof that a CVE is detectable
or exploitable on a given asset. Nothing here runs a scan.
"""
from __future__ import annotations

import re
from datetime import date
from pathlib import Path
from typing import Any

from .common import is_cve, safe_url

NUCLEI_REPO = "https://github.com/projectdiscovery/nuclei-templates"
INTRUSIVE_TAGS = {"intrusive", "dos", "fuzz", "fuzzing", "bruteforce", "brute-force"}
METHODS = {"nuclei", "nmap-nse", "vendor-script", "config-check", "authenticated-check", "manual"}
INVASIVENESS = {"passive", "safe-probe", "intrusive"}
REVIEW = {"reviewed", "unreviewed", "rejected"}

_ID = re.compile(r"^id:\s*['\"]?(CVE-\d{4}-\d{4,})['\"]?\s*$", re.M)
_TAGS = re.compile(r"^\s{2}tags:\s*(.+)$", re.M)
_SEV = re.compile(r"^\s{2}severity:\s*(\w+)", re.M)
_NAME = re.compile(r"^\s{2}name:\s*(.+)$", re.M)
_VERIFIED = re.compile(r"^\s{4}verified:\s*true\s*$", re.M)


def index_nuclei(root: Path, commit: str | None) -> dict[str, list[dict]]:
    """Map CVE -> template references from a nuclei-templates checkout."""
    out: dict[str, list[dict]] = {}
    if not root or not root.is_dir():
        return out
    for path in sorted(root.glob("*/cves/**/CVE-*.yaml")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:20000]
        except OSError:
            continue
        m = _ID.search(text)
        if not m or not is_cve(m.group(1)):
            continue
        cve = m.group(1)
        tags = {t.strip().lower() for t in (_TAGS.search(text).group(1) if _TAGS.search(text) else "").split(",")}
        rel = path.relative_to(root).as_posix()
        protocol = rel.split("/", 1)[0]
        name = _NAME.search(text)
        sev = _SEV.search(text)
        entry = {
            "method": "nuclei",
            "id": cve,
            "name": name.group(1).strip().strip("'\"")[:140] if name else None,
            "path": rel,
            "protocol": protocol,
            "publisher": "ProjectDiscovery nuclei-templates (community)",
            "url": f"{NUCLEI_REPO}/blob/main/{rel}",  # commit recorded once in status.json
            "templateSeverity": sev.group(1).lower() if sev else None,
            "upstreamVerified": bool(_VERIFIED.search(text)),
            "invasiveness": "intrusive" if tags & INTRUSIVE_TAGS else "safe-probe",
            "outOfBand": "oast" in tags,
            "reviewStatus": "unreviewed",
            "lastReviewed": None,
            "reviewNote": None,
        }
        out.setdefault(cve, []).append(entry)
    return out


NMAP_REPO = "https://github.com/nmap/nmap"
_NSE_CVE = re.compile(r"CVE\s*=\s*['\"](CVE-\d{4}-\d{4,})['\"]")
_NSE_FILE_CVE = re.compile(r"cve(\d{4})-(\d{4,})")
_NSE_CATS = re.compile(r"^categories\s*=\s*\{([^}]*)\}", re.M)
NSE_RISKY = {"intrusive", "dos", "exploit", "brute", "fuzzer", "malware"}


def index_nmap(root: Path) -> dict[str, list[dict]]:
    """Map CVE -> official Nmap NSE scripts that declare that CVE."""
    out: dict[str, list[dict]] = {}
    if not root or not root.is_dir():
        return out
    for path in sorted((root / "scripts").glob("*.nse")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        ids = set(_NSE_CVE.findall(text))
        m = _NSE_FILE_CVE.search(path.stem)
        if m:
            ids.add(f"CVE-{m.group(1)}-{m.group(2)}")
        if not ids:
            continue
        cm = _NSE_CATS.search(text)
        cats = sorted({c.strip().strip("'\"") for c in cm.group(1).split(",")} - {""}) if cm else []
        entry = {
            "method": "nmap-nse",
            "id": path.stem,
            "name": path.stem,
            "path": f"scripts/{path.name}",
            "protocol": None,
            "publisher": "Nmap Project (official NSE script)",
            "url": f"{NMAP_REPO}/blob/master/scripts/{path.name}",
            "templateSeverity": None,
            "upstreamVerified": False,
            "categories": cats,
            "invasiveness": "intrusive" if set(cats) & NSE_RISKY else "safe-probe",
            "outOfBand": False,
            "reviewStatus": "unreviewed",
            "lastReviewed": None,
            "reviewNote": None,
        }
        for cve in ids:
            if is_cve(cve):
                out.setdefault(cve, []).append(entry)
    return out


def combine(*indexes: dict[str, list[dict]]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for idx in indexes:
        for k, v in idx.items():
            out.setdefault(k, []).extend(v)
    return out


def load_reviews(raw: Any) -> list[dict]:
    """Validate the Aegis-curated reviews file. Raises ValueError on bad entries."""
    if raw is None:
        return []
    items = raw.get("entries", []) if isinstance(raw, dict) else None
    if not isinstance(items, list):
        raise ValueError("validation/reviews.json must contain an 'entries' list")
    out = []
    for i, e in enumerate(items):
        where = f"reviews.json entry {i}"
        if not is_cve(e.get("cve")):
            raise ValueError(f"{where}: invalid cve")
        if e.get("method") not in METHODS:
            raise ValueError(f"{where}: method must be one of {sorted(METHODS)}")
        if e.get("reviewStatus") not in REVIEW:
            raise ValueError(f"{where}: reviewStatus must be one of {sorted(REVIEW)}")
        if e.get("invasiveness") not in INVASIVENESS:
            raise ValueError(f"{where}: invasiveness must be one of {sorted(INVASIVENESS)}")
        try:
            date.fromisoformat(str(e.get("lastReviewed")))
        except ValueError:
            raise ValueError(f"{where}: lastReviewed must be YYYY-MM-DD") from None
        if not e.get("reviewer"):
            raise ValueError(f"{where}: reviewer required")
        if e.get("url") is not None and not safe_url(e.get("url")):
            raise ValueError(f"{where}: url must be https")
        out.append(e)
    return out


def merge(index: dict[str, list[dict]], reviews: list[dict]) -> dict[str, list[dict]]:
    """Apply reviews: update a matching Nuclei entry, or add a curated method."""
    merged = {k: [dict(x) for x in v] for k, v in index.items()}
    for r in reviews:
        rows = merged.setdefault(r["cve"], [])
        target = None
        if r["method"] in ("nuclei", "nmap-nse") and r.get("path"):
            target = next((x for x in rows if x["method"] == r["method"] and x["path"] == r["path"]), None)
        if target is None:
            target = {"method": r["method"], "id": r.get("id"), "name": r.get("name"), "path": r.get("path"),
                      "protocol": r.get("protocol"), "publisher": r.get("publisher") or "Aegis curated",
                      "url": r.get("url"), "templateSeverity": None, "upstreamVerified": False,
                      "outOfBand": bool(r.get("outOfBand"))}
            rows.append(target)
        target.update({"reviewStatus": r["reviewStatus"], "lastReviewed": r["lastReviewed"],
                       "reviewNote": r.get("note"), "reviewer": r["reviewer"],
                       "invasiveness": r["invasiveness"]})
    for rows in merged.values():  # reviewed first, rejected last
        rows.sort(key=lambda x: ({"reviewed": 0, "unreviewed": 1, "rejected": 2}[x["reviewStatus"]],
                                 x["invasiveness"] == "intrusive", x.get("path") or ""))
    return merged
