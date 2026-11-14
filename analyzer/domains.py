"""Domain helpers shared by the URL and header detectors.

Covers:
* registrable_domain(): "login.paypal.co.uk" -> "paypal.co.uk"
* is_ip_host(): raw IPv4/IPv6 or purely numeric hosts
* brands_in(): which well-known brands a string claims, after leetspeak
  normalisation ("paypa1" -> "paypal")
* brand_owns_domain(): is this the brand's real domain?

We deliberately avoid the full Public Suffix List (a large external
dependency). A small table of common multi-part suffixes is enough for a lab
tool; see docs/threat-model.md for the trade-off.
"""

from __future__ import annotations

import ipaddress
import re
from email.utils import parseaddr

# Two-label public suffixes where the registrable domain needs three labels.
MULTI_PART_SUFFIXES: frozenset[str] = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "org.nz", "co.za", "co.jp", "ne.jp", "or.jp", "co.in", "co.kr",
        "com.br", "com.mx", "com.ar", "com.cn", "com.hk", "com.sg", "com.tr",
        "com.tw", "com.my", "com.pk", "co.id", "co.il",
    }
)

# Brand keyword -> registrable domains the brand really owns.
BRAND_DOMAINS: dict[str, frozenset[str]] = {
    "paypal": frozenset({"paypal.com", "paypal.me", "paypalobjects.com", "paypal.co.uk"}),
    "microsoft": frozenset(
        {
            "microsoft.com", "microsoftonline.com", "live.com", "outlook.com",
            "office.com", "office365.com", "microsoft365.com", "windows.net",
        }
    ),
    "apple": frozenset({"apple.com", "icloud.com", "me.com"}),
    "google": frozenset(
        {"google.com", "gmail.com", "googlemail.com", "googleusercontent.com", "googleapis.com", "google.co.uk"}
    ),
    "amazon": frozenset({"amazon.com", "amazon.co.uk", "amazon.de", "amazonaws.com", "amazon.ca"}),
    "netflix": frozenset({"netflix.com", "netflix.net"}),
    "docusign": frozenset({"docusign.com", "docusign.net"}),
    "dhl": frozenset({"dhl.com", "dhl.de", "dhl.co.uk"}),
}

# Character substitutions attackers use to imitate letters. "1" is ambiguous
# (l or i), so we try both.
_LEET_BASE = str.maketrans({"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a", "!": "i", "|": "l"})
_ONE_AS = ("l", "i")

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def normalize_host(host: str) -> str:
    """Lowercase a host and strip brackets, whitespace and a trailing dot."""
    return host.strip().strip("[]").rstrip(".").lower()


def is_ip_host(host: str) -> bool:
    """True for IPv4/IPv6 literals and all-numeric hosts like 3232235777."""
    host = normalize_host(host)
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Decimal / hex / dotted-octal obfuscation, e.g. http://3232235777/ or 0xC0.0xA8.0.1
    return bool(re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}", host))


def registrable_domain(host: str) -> str:
    """Return the domain a person would register, e.g. 'evil.co.uk'.

    IPs are returned unchanged. Handles the multi-part suffixes listed above.
    """
    host = normalize_host(host)
    if not host or is_ip_host(host):
        return host
    labels = [label for label in host.split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def domain_of_address(address: str) -> str:
    """Return the lowercase domain of an email address ('' if none)."""
    _, addr = parseaddr(address or "")
    if "@" not in addr:
        return ""
    return normalize_host(addr.rsplit("@", 1)[1])


def leet_variants(text: str) -> set[str]:
    """Return normalised forms of text with leetspeak undone.

    Non-alphanumeric characters are dropped so "pay-pal" and "Pay Pal" both
    become "paypal". "rn" is also tried as "m" (rnicrosoft -> microsoft).
    """
    lowered = text.lower().translate(_LEET_BASE)
    variants: set[str] = set()
    for one in _ONE_AS:
        candidate = re.sub(r"[^a-z]", "", lowered.replace("1", one))
        variants.add(candidate)
        variants.add(candidate.replace("rn", "m"))
    return variants


def brands_in(text: str) -> list[str]:
    """Return the brand keywords that appear in text (leetspeak-aware)."""
    variants = leet_variants(text)
    return [brand for brand in BRAND_DOMAINS if any(brand in v for v in variants)]


def brand_owns_domain(brand: str, domain: str) -> bool:
    """True if the registrable domain of `domain` belongs to `brand`."""
    return registrable_domain(domain) in BRAND_DOMAINS.get(brand, frozenset())


def emails_in(text: str) -> list[str]:
    """Return email addresses found anywhere in text."""
    return _EMAIL_RE.findall(text or "")
