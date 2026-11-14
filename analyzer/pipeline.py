"""The analysis pipeline: raw .eml bytes in, AnalysisResult out.

    raw bytes -> parse_email -> [headers, urls, keywords, attachments] -> score

Each detector is independent and returns (details, indicators). The pipeline
just wires them together, so adding a new detector means one more line here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .attachments import AttachmentFinding, analyze_attachments
from .headers import HeaderReport, analyze_headers
from .indicators import Indicator
from .keywords import analyze_keywords
from .parser import EmailParseError, ParsedEmail, parse_email
from .scoring import ScoreResult, score_indicators
from .urls import URLFinding, analyze_urls

MAX_EMAIL_BYTES = 15 * 1024 * 1024  # refuse absurdly large inputs


@dataclass
class AnalysisResult:
    """Everything the UI, CLI, report and LLM need about one email."""

    parsed: ParsedEmail
    headers: HeaderReport
    urls: list[URLFinding]
    keyword_hits: dict[str, list[str]]
    attachments: list[AttachmentFinding]
    indicators: list[Indicator]  # sorted by points, highest first
    score: ScoreResult
    source_name: str = ""
    extra: dict = field(default_factory=dict)  # optional add-ons, e.g. VirusTotal results


def analyze(raw: bytes, source_name: str = "") -> AnalysisResult:
    """Analyze one email given as raw .eml bytes.

    Raises:
        analyzer.parser.EmailParseError: if the input isn't a parseable email.
    """
    if isinstance(raw, (bytes, bytearray)) and len(raw) > MAX_EMAIL_BYTES:
        raise EmailParseError(f"File is larger than {MAX_EMAIL_BYTES // (1024 * 1024)} MB.")

    parsed = parse_email(raw)
    header_report, header_ind = analyze_headers(parsed)
    url_findings, url_ind = analyze_urls(parsed)
    keyword_hits, keyword_ind = analyze_keywords(parsed)
    attachment_findings, attachment_ind = analyze_attachments(parsed)

    indicators = sorted(header_ind + url_ind + keyword_ind + attachment_ind, key=lambda i: -i.points)
    return AnalysisResult(
        parsed=parsed,
        headers=header_report,
        urls=url_findings,
        keyword_hits=keyword_hits,
        attachments=attachment_findings,
        indicators=indicators,
        score=score_indicators(indicators),
        source_name=source_name,
    )


def analyze_file(path: str | Path) -> AnalysisResult:
    """Convenience wrapper: read an .eml file from disk and analyze it."""
    path = Path(path)
    return analyze(path.read_bytes(), source_name=path.name)
