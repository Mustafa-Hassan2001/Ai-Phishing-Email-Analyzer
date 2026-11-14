"""URL extraction and URL heuristics.

URLs come from two places:
* the plain-text body (regex), and
* the HTML body (<a href> and <form action>), together with the visible
  anchor text so we can spot "text says paypal.com, link goes elsewhere".

Nothing is ever fetched: every check works on the URL string alone.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit

from .domains import BRAND_DOMAINS, brand_owns_domain, brands_in, is_ip_host, normalize_host, registrable_domain
from .html_utils import extract_links
from .indicators import URLS, Indicator, dedupe
from .parser import ParsedEmail

URL_RE = re.compile(r"""(?:https?://|www\.)[^\s<>"'`]+""", re.IGNORECASE)
_TRAILING_PUNCT = ".,;:!?)]}>'\""

# Anchor text that *looks like* a URL or bare domain, e.g. "www.paypal.com/login".
_TEXT_AS_URL_RE = re.compile(r"^(?:https?://)?([a-z0-9.\-]+\.[a-z]{2,})(?:[/:?#]\S*)?/?$", re.IGNORECASE)

SHORTENERS: frozenset[str] = frozenset(
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
        "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id", "t.ly", "bl.ink", "lnkd.in",
    }
)

SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {
        "xyz", "top", "zip", "mov", "click", "link", "work", "gq", "tk", "ml", "cf", "ga",
        "buzz", "rest", "country", "kim", "loan", "cam", "monster", "quest", "sbs", "cfd",
    }
)

LONG_URL_LENGTH = 100
MAX_SUBDOMAIN_DEPTH = 2  # labels before the registrable domain; 3+ is suspicious
MAX_HOST_HYPHENS = 2

# Points per rule. Tuned so a single weak signal stays "Low" on its own.
POINTS: dict[str, int] = {
    "ip_host": 20,
    "shortener": 10,
    "punycode": 15,
    "at_sign": 15,
    "http": 5,
    "suspicious_tld": 10,
    "subdomains": 5,
    "long_url": 5,
    "hyphens": 5,
    "brand_impersonation": 25,
    "text_mismatch": 20,
}


@dataclass
class ExtractedURL:
    """A URL as found in the email, before analysis."""

    url: str
    source: str  # "text" or "html"
    anchor_text: str = ""


@dataclass
class URLFinding:
    """A URL plus the results of every heuristic."""

    url: str
    source: str
    anchor_text: str
    host: str
    registrable_domain: str
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _clean(raw: str) -> str:
    """Trim whitespace/trailing punctuation and add a scheme to www. URLs."""
    url = raw.strip().rstrip(_TRAILING_PUNCT)
    if url.lower().startswith("www."):
        url = "http://" + url
    return url


def extract_urls(parsed: ParsedEmail) -> list[ExtractedURL]:
    """Return unique URLs from the HTML body (with anchor text) and text body."""
    found: list[ExtractedURL] = []
    seen_urls: set[str] = set()

    for href, anchor in extract_links(parsed.html_body):
        url = _clean(href)
        if not url.lower().startswith(("http://", "https://")):
            continue  # mailto:, tel:, #anchors, relative links
        key = (url, anchor)
        if key not in {(u.url, u.anchor_text) for u in found}:
            found.append(ExtractedURL(url, "html", anchor))
            seen_urls.add(url)

    for match in URL_RE.findall(parsed.text_body):
        url = _clean(match)
        if url not in seen_urls:
            found.append(ExtractedURL(url, "text"))
            seen_urls.add(url)
    return found


def _anchor_domain(anchor_text: str) -> str:
    """If the anchor text looks like a URL/domain, return its host."""
    match = _TEXT_AS_URL_RE.match(anchor_text.strip())
    return normalize_host(match.group(1)) if match else ""


def check_url(item: ExtractedURL) -> tuple[URLFinding, list[Indicator]]:
    """Run every URL heuristic on one URL."""
    try:
        parts = urlsplit(item.url)
        host = normalize_host(parts.hostname or "")
    except ValueError:  # e.g. invalid IPv6 literal
        parts, host = None, ""
    domain = registrable_domain(host)
    finding = URLFinding(item.url, item.source, item.anchor_text, host, domain)
    indicators: list[Indicator] = []

    def flag(rule: str, description: str) -> None:
        finding.flags.append(rule)
        indicators.append(Indicator(URLS, POINTS[rule], description, item.url))

    if parts is None or not host:
        return finding, indicators

    labels = host.split(".")
    if is_ip_host(host):
        flag("ip_host", "Link points to a raw IP address instead of a domain name")
    if host in SHORTENERS or domain in SHORTENERS:
        flag("shortener", f"Link uses a URL shortener ({domain}) that hides the real destination")
    if not host.isascii() or any(label.startswith("xn--") for label in labels):
        flag("punycode", "Link uses a punycode/internationalised domain that can imitate another site")
    if "@" in parts.netloc:
        flag("at_sign", "Link contains '@': the browser ignores everything before it")
    if parts.scheme == "http":
        flag("http", "Link uses unencrypted http://")
    if labels[-1] in SUSPICIOUS_TLDS and not is_ip_host(host):
        flag("suspicious_tld", f"Link uses a top-level domain often abused for phishing (.{labels[-1]})")
    if not is_ip_host(host) and len(labels) - len(domain.split(".")) > MAX_SUBDOMAIN_DEPTH:
        flag("subdomains", "Link has an unusually deep chain of subdomains")
    if len(item.url) > LONG_URL_LENGTH:
        flag("long_url", f"Link is very long ({len(item.url)} characters)")
    if host.replace("xn--", "").count("-") > MAX_HOST_HYPHENS:  # punycode's own "--" doesn't count
        flag("hyphens", "Domain contains many hyphens")

    impersonated = [b for b in brands_in(host) if not brand_owns_domain(b, domain)]
    if impersonated:
        real = ", ".join(sorted(BRAND_DOMAINS[impersonated[0]]))
        flag(
            "brand_impersonation",
            f"Domain imitates the brand '{impersonated[0]}' but is not one of its real domains ({real})",
        )

    shown = _anchor_domain(item.anchor_text)
    if shown and registrable_domain(shown) != domain:
        flag("text_mismatch", f"Link text shows '{shown}' but actually goes to '{host}'")
    return finding, indicators


def analyze_urls(parsed: ParsedEmail) -> tuple[list[URLFinding], list[Indicator]]:
    """Extract and check all URLs. Returns (findings, indicators)."""
    findings: list[URLFinding] = []
    indicators: list[Indicator] = []
    for item in extract_urls(parsed):
        finding, found = check_url(item)
        findings.append(finding)
        indicators.extend(found)
    return findings, dedupe(indicators)
