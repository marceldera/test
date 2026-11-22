"""Shared helpers for the ThreatWatch publisher (standard library only)."""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

ET = ZoneInfo("America/New_York")
UTC = timezone.utc
USER_AGENT = "AegisThreatWatch/1.0 (+https://aegisdefensecyber.com/threatwatch/)"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
SAFE_URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+(?::\d+)?(?:/[^\s<>\"']*)?$")

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.environ.get("TW_DATA_DIR") or REPO_ROOT / "threatwatch" / "data")


class SourceError(RuntimeError):
    """A public source could not be fetched or failed validation."""


def now_utc() -> datetime:
    override = os.environ.get("TW_NOW")  # ISO timestamp, for tests only
    if override:
        return datetime.fromisoformat(override).astimezone(UTC)
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def is_cve(value: Any) -> bool:
    return isinstance(value, str) and bool(CVE_RE.match(value))


def safe_url(value: Any) -> str | None:
    """Return the URL only if it is a plain https URL; otherwise None."""
    if isinstance(value, str) and SAFE_URL_RE.match(value.strip()):
        return value.strip()
    return None


def fetch_json(url: str, *, headers: dict | None = None, timeout: int = 45,
               retries: int = 3, backoff: float = 5.0) -> Any:
    fixture_dir = os.environ.get("TW_FIXTURES")
    if fixture_dir:  # offline test mode: map URL -> fixture file
        return _fixture_for(url, Path(fixture_dir))
    last: Exception | None = None
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                                   "Accept": "application/json",
                                                   **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    raise SourceError(f"HTTP {resp.status} from {url}")
                raw = resp.read(150 * 1024 * 1024)  # 150 MB ceiling
            return json.loads(raw)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, SourceError) as exc:
            last = exc
            if isinstance(exc, urllib.error.HTTPError) and exc.code in (400, 401, 403, 404):
                break
            if attempt < retries:
                time.sleep(backoff * attempt)
    raise SourceError(f"Failed to fetch {url}: {last}")


def fetch_text(url: str, *, headers: dict | None = None, timeout: int = 120,
               retries: int = 3, backoff: float = 5.0, limit_mb: int = 200) -> str:
    """Fetch a text/CSV/large-JSON body. Offline test mode maps URLs to fixture files."""
    fixture_dir = os.environ.get("TW_FIXTURES")
    if fixture_dir:
        path = Path(fixture_dir) / _fixture_name(url)
        if not path.exists():
            raise SourceError(f"Fixture missing: {path.name}")
        return path.read_text(encoding="utf-8")
    last: Exception | None = None
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    raise SourceError(f"HTTP {resp.status} from {url}")
                return resp.read(limit_mb * 1024 * 1024).decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError, SourceError) as exc:
            last = exc
            if isinstance(exc, urllib.error.HTTPError) and exc.code in (400, 401, 403, 404):
                break
            if attempt < retries:
                time.sleep(backoff * attempt)
    raise SourceError(f"Failed to fetch {url}: {last}")


def _fixture_name(url: str) -> str:
    """Fixture file names for the enrichment feeds (offline tests)."""
    table = [("docs.google.com/spreadsheets", "p0-{sheet}.csv"), ("modules_metadata_base", "msf.json"),
             ("files_exploits.csv", "edb.csv"), ("enterprise-attack.json", "attack.json"),
             ("mappings-explorer", "ctid-kev.json"), ("euvdservices", "euvd-{page}.json"),
             ("api.vulncheck.com", "vulncheck-{page}.json")]
    for needle, name in table:
        if needle in url:
            sheet = re.search(r"sheet=([^&]+)", url)
            page = re.search(r"[?&]page=(\d+)", url)
            return name.format(sheet=sheet.group(1) if sheet else "x", page=page.group(1) if page else 0)
    return "unmapped.txt"


def _fixture_for(url: str, fixture_dir: Path) -> Any:
    if any(n in url for n in ("euvdservices", "api.vulncheck.com", "mappings-explorer", "modules_metadata_base")):
        name = _fixture_name(url)
    elif "known_exploited_vulnerabilities" in url:
        name = "kev.json"
    elif "api.first.org" in url:
        name = "epss.json"
    elif "services.nvd.nist.gov" in url and "lastModStartDate" in url:
        m = re.search(r"startIndex=(\d+)", url)
        name = f"nvd-bulk-{m.group(1) if m else 0}.json"
    elif "services.nvd.nist.gov" in url and "pubStartDate" in url:
        m = re.search(r"startIndex=(\d+)", url)
        name = f"nvd-pub-{m.group(1) if m else 0}.json"
    elif "services.nvd.nist.gov" in url:
        m = re.search(r"cveId=(CVE-\d{4}-\d+)", url)
        name = f"nvd-{m.group(1)}.json" if m else "nvd.json"
    else:
        raise SourceError(f"No fixture for {url}")
    path = fixture_dir / name
    if not path.exists():
        raise SourceError(f"Fixture missing: {path.name}")
    return json.loads(path.read_text())


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(path)
