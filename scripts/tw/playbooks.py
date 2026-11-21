"""Validation playbooks: product library (read-only version checks) and
Aegis-curated per-CVE playbooks. Both are hand-maintained JSON under
threatwatch/data/validation/ and are validated before anything publishes.
"""
from __future__ import annotations

import re
from datetime import date
from typing import Any

from .common import is_cve, safe_url

PLATFORMS = {"linux", "windows", "macos", "kubernetes", "container", "appliance-cli", "web-ui", "network"}
STAGES = ["inventory", "configuration", "exposure", "detection", "mitigation", "verification"]
INVASIVENESS = {"passive", "safe-probe", "intrusive"}
_CPE = re.compile(r"^[a-z0-9_.\-]+:[a-z0-9_.\-*]+$")


def _date(v: Any, where: str) -> None:
    try:
        date.fromisoformat(str(v))
    except ValueError:
        raise ValueError(f"{where}: date must be YYYY-MM-DD") from None


def _cmd(v: Any, where: str) -> None:
    if not isinstance(v, str) or not v.strip() or len(v) > 2000:
        raise ValueError(f"{where}: cmd must be a non-empty string under 2000 characters")


def load_products(raw: Any) -> list[dict]:
    items = raw.get("products") if isinstance(raw, dict) else None
    if not isinstance(items, list):
        raise ValueError("products.json must contain a 'products' list")
    seen = set()
    for i, p in enumerate(items):
        w = f"products.json [{i}] {p.get('id')}"
        if not p.get("id") or p["id"] in seen:
            raise ValueError(f"{w}: unique id required")
        seen.add(p["id"])
        if not p.get("label"):
            raise ValueError(f"{w}: label required")
        if not p.get("cpe") or not all(isinstance(c, str) and _CPE.match(c) for c in p["cpe"]):
            raise ValueError(f"{w}: cpe must list vendor:product keys (lowercase, * allowed)")
        for j, c in enumerate(p.get("checks", [])):
            cw = f"{w} check {j}"
            if c.get("platform") not in PLATFORMS:
                raise ValueError(f"{cw}: platform must be one of {sorted(PLATFORMS)}")
            if not c.get("label"):
                raise ValueError(f"{cw}: label required")
            _cmd(c.get("cmd"), cw)
            if c.get("extract"):
                try:
                    re.compile(c["extract"])
                except re.error:
                    raise ValueError(f"{cw}: extract is not a valid regex") from None
        if not all(isinstance(x, int) and 0 < x < 65536 for x in p.get("ports", [])):
            raise ValueError(f"{w}: ports must be integers 1-65535")
        for u in p.get("sources", []):
            if not safe_url(u):
                raise ValueError(f"{w}: source URLs must be https")
    return items


def load_playbooks(raw: Any) -> dict[str, dict]:
    items = raw.get("playbooks") if isinstance(raw, dict) else None
    if not isinstance(items, list):
        raise ValueError("playbooks.json must contain a 'playbooks' list")
    out: dict[str, dict] = {}
    for i, pb in enumerate(items):
        w = f"playbooks.json [{i}] {pb.get('cve')}"
        if not is_cve(pb.get("cve")) or pb["cve"] in out:
            raise ValueError(f"{w}: valid, unique cve required")
        if not pb.get("reviewedBy"):
            raise ValueError(f"{w}: reviewedBy required")
        _date(pb.get("lastReviewed"), w)
        srcs = pb.get("sources") or []
        if not srcs or not all(safe_url(u) for u in srcs):
            raise ValueError(f"{w}: at least one https source required")
        for j, f in enumerate(pb.get("fixedVersions", [])):
            if not f.get("product") or not f.get("fixed"):
                raise ValueError(f"{w} fixedVersions {j}: product and fixed required")
        for j, st in enumerate(pb.get("steps", [])):
            sw = f"{w} step {j}"
            if st.get("stage") not in STAGES:
                raise ValueError(f"{sw}: stage must be one of {STAGES}")
            if st.get("platform") not in PLATFORMS:
                raise ValueError(f"{sw}: platform must be one of {sorted(PLATFORMS)}")
            if st.get("invasiveness") not in INVASIVENESS:
                raise ValueError(f"{sw}: invasiveness must be one of {sorted(INVASIVENESS)}")
            if not st.get("title") or not st.get("positive") or not st.get("negative"):
                raise ValueError(f"{sw}: title, positive and negative are required")
            _cmd(st.get("cmd"), sw)
        out[pb["cve"]] = pb
    return out
