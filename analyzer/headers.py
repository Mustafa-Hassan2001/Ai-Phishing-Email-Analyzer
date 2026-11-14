"""Header analysis: SPF/DKIM/DMARC results and sender identity checks.

Important: we *read* authentication results that the receiving mail server
already wrote into Authentication-Results / Received-SPF. We do not perform
DNS lookups ourselves, so the tool works offline. Those headers can be forged
by the sender if your mail server doesn't strip them; see docs/threat-model.md.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from email.utils import getaddresses

from .domains import brand_owns_domain, brands_in, domain_of_address, emails_in, registrable_domain
from .indicators import HEADERS, Indicator
from .parser import ParsedEmail

MECHANISMS = ("spf", "dkim", "dmarc")
_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)

# Points for each (mechanism, result). Results not listed score 0 (e.g. pass).
AUTH_POINTS: dict[str, dict[str, int]] = {
    "spf": {"fail": 20, "softfail": 10, "missing": 5, "none": 5, "neutral": 5, "permerror": 5, "temperror": 3},
    "dkim": {"fail": 15, "missing": 5, "none": 5, "neutral": 5, "permerror": 5, "temperror": 3, "policy": 5},
    "dmarc": {"fail": 20, "missing": 5, "none": 5, "permerror": 5, "temperror": 3},
}

POINTS: dict[str, int] = {
    "missing_from": 15,
    "missing_message_id": 5,
    "reply_to_mismatch": 15,
    "return_path_mismatch": 8,
    "display_name_brand": 20,
    "display_name_email": 15,
}


@dataclass
class Hop:
    """One entry of the Received chain (oldest hop first)."""

    from_host: str
    by_host: str
    date: str


@dataclass
class HeaderReport:
    """Summary of identity and authentication headers."""

    from_header: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to: str = ""
    return_path: str = ""
    message_id: str = ""
    auth: dict[str, str] = field(default_factory=dict)
    received: list[Hop] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def parse_auth_results(parsed: ParsedEmail) -> dict[str, str]:
    """Return {"spf": result, "dkim": result, "dmarc": result}.

    The first (topmost) Authentication-Results header wins because it was
    added by the final receiving server, the one we trust most. Received-SPF
    is used as a fallback for SPF. Unknown -> "missing".
    """
    results: dict[str, str] = {}
    for header in parsed.get_all("Authentication-Results"):
        for mechanism, value in _RESULT_RE.findall(header):
            results.setdefault(mechanism.lower(), value.lower())
    if "spf" not in results:
        for header in parsed.get_all("Received-SPF"):
            words = header.split()
            if words:
                results["spf"] = words[0].lower().strip(";:")
                break
    return {mechanism: results.get(mechanism, "missing") for mechanism in MECHANISMS}


def parse_received_chain(parsed: ParsedEmail) -> list[Hop]:
    """Parse Received headers into hops, oldest first (display only)."""
    hops: list[Hop] = []
    for header in reversed(parsed.get_all("Received")):
        from_match = re.search(r"\bfrom\s+([^\s;]+)(?:\s+\(([^)]*)\))?", header, re.IGNORECASE)
        by_match = re.search(r"\bby\s+([^\s;]+)", header, re.IGNORECASE)
        from_host = from_match.group(1) if from_match else ""
        if from_match and from_match.group(2):
            from_host += f" ({from_match.group(2)})"
        date = header.rsplit(";", 1)[1].strip() if ";" in header else ""
        hops.append(Hop(from_host, by_match.group(1) if by_match else "", date))
    return hops


def _check_auth(auth: dict[str, str]) -> list[Indicator]:
    indicators: list[Indicator] = []
    for mechanism, result in auth.items():
        points = AUTH_POINTS[mechanism].get(result, 0)
        if not points:
            continue
        if result in ("missing", "none"):
            description = f"No {mechanism.upper()} result: the sender could not be authenticated"
        else:
            description = f"{mechanism.upper()} check returned '{result}'"
        indicators.append(Indicator(HEADERS, points, description, f"{mechanism}={result}"))
    return indicators


def _check_identity(parsed: ParsedEmail, from_domain: str) -> list[Indicator]:
    indicators: list[Indicator] = []
    from_reg = registrable_domain(from_domain)

    reply_domains = {registrable_domain(addr.split("@")[-1]) for _, addr in getaddresses([parsed.reply_to]) if "@" in addr}
    mismatched = sorted(d for d in reply_domains if d and d != from_reg)
    if mismatched:
        indicators.append(
            Indicator(HEADERS, POINTS["reply_to_mismatch"],
                      "Reply-To sends your answer to a different domain than From",
                      f"From: {from_reg} / Reply-To: {', '.join(mismatched)}")
        )

    return_domain = registrable_domain(domain_of_address(parsed.return_path))
    if return_domain and return_domain != from_reg:
        indicators.append(
            Indicator(HEADERS, POINTS["return_path_mismatch"],
                      "Return-Path (envelope sender) domain differs from From",
                      f"From: {from_reg} / Return-Path: {return_domain}")
        )

    display = parsed.from_display
    claimed = [b for b in brands_in(display) if not brand_owns_domain(b, from_domain)]
    if claimed:
        indicators.append(
            Indicator(HEADERS, POINTS["display_name_brand"],
                      f"Display name claims to be '{claimed[0]}' but the sending domain does not belong to it",
                      f"{display} <{parsed.from_address}>")
        )

    foreign = [e for e in emails_in(display) if e.lower() != parsed.from_address]
    if foreign:
        indicators.append(
            Indicator(HEADERS, POINTS["display_name_email"],
                      "Display name contains a different email address than the real sender",
                      f"{display} <{parsed.from_address}>")
        )
    return indicators


def analyze_headers(parsed: ParsedEmail) -> tuple[HeaderReport, list[Indicator]]:
    """Run all header checks. Returns (report, indicators)."""
    from_domain = domain_of_address(parsed.from_header)
    report = HeaderReport(
        from_header=parsed.from_header,
        from_address=parsed.from_address,
        from_domain=from_domain,
        reply_to=parsed.reply_to,
        return_path=parsed.return_path,
        message_id=parsed.message_id,
        auth=parse_auth_results(parsed),
        received=parse_received_chain(parsed),
    )

    indicators = _check_auth(report.auth)
    if not parsed.message_id:
        indicators.append(Indicator(HEADERS, POINTS["missing_message_id"], "Message-ID header is missing", ""))
    if not from_domain:
        indicators.append(Indicator(HEADERS, POINTS["missing_from"], "From header is missing or has no valid address",
                                    parsed.from_header))
    else:
        indicators.extend(_check_identity(parsed, from_domain))
    return report, indicators
