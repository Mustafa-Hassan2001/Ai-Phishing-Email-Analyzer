"""Markdown and JSON reports.

* JSON keeps raw values (machine-readable, for SIEMs or scripts).
* Markdown defangs URLs (hxxp://evil[.]example) and escapes table pipes, so
  opening the report in a Markdown viewer never produces a clickable
  malicious link.

Email bodies are not included in either report, only the findings.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from . import __version__
from .scoring import CATEGORY_CAPS

if TYPE_CHECKING:  # avoid a runtime import cycle with llm.py
    from .llm import Explanation
    from .pipeline import AnalysisResult


def defang(text: str) -> str:
    """Make a URL or domain non-clickable: http -> hxxp, '.' -> '[.]'."""
    return text.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


_URL_TOKEN_RE = re.compile(r"\b(?:https?://|www\.)\S+", re.IGNORECASE)


def defang_urls(text: str) -> str:
    """Defang only the URL-looking tokens inside free text (e.g. LLM output)."""
    return _URL_TOKEN_RE.sub(lambda m: defang(m.group(0)), text)


def _cell(value: object) -> str:
    """Make a value safe inside a Markdown table cell."""
    text = " ".join(str(value).split())
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")


def to_dict(result: AnalysisResult, explanation: Explanation | None = None) -> dict:
    """Return the full report as a JSON-serialisable dict."""
    parsed = result.parsed
    data = {
        "tool": f"phishing-analyzer {__version__}",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": result.source_name,
        "email": {
            "subject": parsed.subject,
            "from": parsed.from_header,
            "to": parsed.to,
            "date": parsed.date,
            "reply_to": parsed.reply_to,
            "return_path": parsed.return_path,
            "message_id": parsed.message_id,
            "text_body_chars": len(parsed.text_body),
            "html_body_chars": len(parsed.html_body),
            "parse_defects": parsed.defects,
        },
        "score": result.score.to_dict(),
        "indicators": [i.to_dict() for i in result.indicators],
        "headers": result.headers.to_dict(),
        "urls": [u.to_dict() for u in result.urls],
        "keywords": result.keyword_hits,
        "attachments": [a.to_dict() for a in result.attachments],
    }
    if result.extra:
        data["extra"] = result.extra
    if explanation is not None:
        data["explanation"] = explanation.to_dict()
    return data


def to_json(result: AnalysisResult, explanation: Explanation | None = None) -> str:
    """Return the report as pretty-printed JSON."""
    return json.dumps(to_dict(result, explanation), indent=2, ensure_ascii=False)


def to_markdown(result: AnalysisResult, explanation: Explanation | None = None) -> str:
    """Return a human-readable Markdown report."""
    score, parsed, hdr = result.score, result.parsed, result.headers
    lines: list[str] = [
        "# Phishing Analysis Report",
        "",
        f"- **Source file:** {_cell(result.source_name or '(uploaded)')}",
        f"- **Subject:** {_cell(parsed.subject)}",
        f"- **From:** {_cell(defang(parsed.from_header))}",
        f"- **Risk score:** {score.total}/100",
        f"- **Risk level:** {score.level}",
        f"- **Recommendation:** {score.recommendation}",
        "",
        "## Category breakdown",
        "",
        "| Category | Raw points | Capped score | Cap |",
        "|---|---|---|---|",
    ]
    for category, capped in score.category_scores.items():
        lines.append(f"| {category} | {score.raw_category_points[category]} | {capped} | {CATEGORY_CAPS[category]} |")

    lines += ["", "## Indicators", ""]
    if result.indicators:
        lines += ["| Points | Category | Finding | Evidence |", "|---|---|---|---|"]
        for ind in result.indicators:
            lines.append(f"| {ind.points} | {ind.category} | {_cell(ind.description)} | {_cell(defang(ind.evidence))} |")
    else:
        lines.append("No suspicious indicators found.")

    lines += [
        "",
        "## Authentication and identity",
        "",
        f"- SPF: {hdr.auth.get('spf')} | DKIM: {hdr.auth.get('dkim')} | DMARC: {hdr.auth.get('dmarc')}",
        f"- Reply-To: {_cell(defang(hdr.reply_to) or '(none)')}",
        f"- Return-Path: {_cell(defang(hdr.return_path) or '(none)')}",
        f"- Message-ID: {_cell(hdr.message_id or '(missing)')}",
        "",
        "## URLs (defanged)",
        "",
    ]
    if result.urls:
        lines += ["| URL | Anchor text | Flags |", "|---|---|---|"]
        for url in result.urls:
            lines.append(f"| {_cell(defang(url.url))} | {_cell(defang(url.anchor_text))} | {', '.join(url.flags) or '-'} |")
    else:
        lines.append("No URLs found.")

    lines += ["", "## Attachments (never opened)", ""]
    if result.attachments:
        lines += ["| Filename | Type | Size | SHA-256 | Flags |", "|---|---|---|---|---|"]
        for att in result.attachments:
            lines.append(
                f"| {_cell(att.filename)} | {_cell(att.content_type)} | {att.size} | `{att.sha256}` | {', '.join(att.flags) or '-'} |"
            )
    else:
        lines.append("No attachments.")

    if explanation is not None:
        lines += ["", f"## AI explanation (source: {explanation.source})", "", defang_urls(explanation.text)]
    lines.append("")
    return "\n".join(lines)
