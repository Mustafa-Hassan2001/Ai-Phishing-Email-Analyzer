"""Optional VirusTotal reputation lookups (stretch feature, OFF by default).

Enabled only when BOTH are true:
  1. the VT_API_KEY environment variable is set, and
  2. the caller explicitly asks for it (CLI --vt, or the UI checkbox).

What is sent: attachment SHA-256 hashes and URLs (looked up, never
submitted for scanning). File contents are never uploaded. URLs can still
contain identifying data (e.g. ?user=alice), so think before enabling it.

Results are informational and do NOT change the rule-based score.
The free API tier allows 4 requests/minute, so lookups are capped.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .pipeline import AnalysisResult

API_BASE = "https://www.virustotal.com/api/v3"
ENV_VAR = "VT_API_KEY"
MAX_LOOKUPS = 4
TIMEOUT = 15.0


def api_key() -> str:
    """Return the API key from the environment ('' if not configured)."""
    return os.environ.get(ENV_VAR, "").strip()


def is_configured() -> bool:
    return bool(api_key())


def url_id(url: str) -> str:
    """VirusTotal URL identifier: unpadded base64url of the URL."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _get(path: str, key: str) -> dict:
    request = urllib.request.Request(f"{API_BASE}{path}", headers={"x-apikey": key, "accept": "application/json"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310 - fixed https URL
        return json.loads(response.read().decode("utf-8"))


def _lookup(kind: str, target: str, path: str, key: str) -> dict:
    """Return a small summary dict; never raises."""
    summary = {"kind": kind, "target": target, "status": "ok"}
    try:
        stats = _get(path, key)["data"]["attributes"]["last_analysis_stats"]
        summary.update({k: int(stats.get(k, 0)) for k in ("malicious", "suspicious", "harmless", "undetected")})
    except urllib.error.HTTPError as exc:
        summary["status"] = "not_found" if exc.code == 404 else f"error: HTTP {exc.code}"
    except (urllib.error.URLError, OSError, KeyError, ValueError, TypeError) as exc:
        summary["status"] = f"error: {exc}"
    return summary


def lookup_hash(sha256: str, key: str) -> dict:
    return _lookup("file", sha256, f"/files/{sha256}", key)


def lookup_url(url: str, key: str) -> dict:
    return _lookup("url", url, f"/urls/{url_id(url)}", key)


def enrich(result: AnalysisResult, enabled: bool, max_lookups: int = MAX_LOOKUPS) -> list[dict]:
    """Look up attachment hashes first, then URLs. Stores results in result.extra.

    Returns [] (and makes no network calls) unless enabled and configured.
    """
    key = api_key()
    if not enabled or not key:
        return []
    targets = [("file", a.sha256) for a in result.attachments] + [("url", u.url) for u in result.urls]
    lookups = [
        lookup_hash(target, key) if kind == "file" else lookup_url(target, key)
        for kind, target in targets[:max_lookups]
    ]
    result.extra["virustotal"] = lookups
    return lookups
