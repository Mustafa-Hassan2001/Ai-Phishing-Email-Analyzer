"""The Indicator dataclass: one suspicious finding with a point value.

Every detector (urls, keywords, headers, attachments) returns a list of
Indicators. The scoring module only ever looks at Indicators, which keeps the
detectors independent of each other and of the scoring rules.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

# Category names. Scoring caps are keyed by these strings.
HEADERS = "headers"
URLS = "urls"
KEYWORDS = "keywords"
ATTACHMENTS = "attachments"

CATEGORIES: tuple[str, ...] = (HEADERS, URLS, KEYWORDS, ATTACHMENTS)


@dataclass(frozen=True)
class Indicator:
    """A single suspicious signal found in an email.

    Attributes:
        category: One of CATEGORIES ("headers", "urls", "keywords", "attachments").
        points: How much this finding adds to the risk score (before caps).
        description: Plain-English explanation of what was found.
        evidence: The specific value that triggered it (a URL, a header, ...).
    """

    category: str
    points: int
    description: str
    evidence: str = ""

    def to_dict(self) -> dict:
        """Return a JSON-friendly dict."""
        return asdict(self)


def dedupe(indicators: list[Indicator]) -> list[Indicator]:
    """Drop exact duplicates while keeping the original order.

    The same URL often appears in both the text and HTML parts of an email;
    without this it would be counted twice.
    """
    seen: set[Indicator] = set()
    unique: list[Indicator] = []
    for indicator in indicators:
        if indicator not in seen:
            seen.add(indicator)
            unique.append(indicator)
    return unique
