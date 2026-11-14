"""Turn indicators into a 0-100 risk score and a level.

Rules:
1. Sum the points of all indicators in each category.
2. Cap each category (CATEGORY_CAPS) so one noisy category, such as many
   keyword hits, can't push an email to Critical on its own.
3. Add the capped category scores and clamp the total to 0-100.

This rule-based score is the single source of truth. The LLM explanation
reads it but can never change it.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .indicators import ATTACHMENTS, CATEGORIES, HEADERS, KEYWORDS, URLS, Indicator

CATEGORY_CAPS: dict[str, int] = {
    HEADERS: 40,
    URLS: 40,
    KEYWORDS: 30,
    ATTACHMENTS: 45,
}

# (minimum score, level), checked from the top down.
LEVELS: tuple[tuple[int, str], ...] = ((75, "Critical"), (50, "High"), (25, "Medium"), (0, "Low"))

RECOMMENDATIONS: dict[str, str] = {
    "Low": "No strong phishing signals. Still confirm unexpected requests through a channel you already trust.",
    "Medium": "Some suspicious signals. Don't click links or open attachments until you've verified the sender another way.",
    "High": "Likely phishing. Don't click, reply, or open attachments; report it to your security team.",
    "Critical": "Almost certainly phishing. Don't interact with it at all; report it and delete it.",
}


@dataclass
class ScoreResult:
    """Final score plus the per-category breakdown."""

    total: int
    level: str
    recommendation: str
    category_scores: dict[str, int] = field(default_factory=dict)  # after caps
    raw_category_points: dict[str, int] = field(default_factory=dict)  # before caps

    def to_dict(self) -> dict:
        return asdict(self)


def level_for(score: int) -> str:
    """Map a 0-100 score to Low / Medium / High / Critical."""
    for minimum, level in LEVELS:
        if score >= minimum:
            return level
    return "Low"


def score_indicators(indicators: list[Indicator]) -> ScoreResult:
    """Combine indicators into a capped 0-100 score."""
    raw = {category: 0 for category in CATEGORIES}
    for indicator in indicators:
        raw[indicator.category] = raw.get(indicator.category, 0) + max(indicator.points, 0)

    capped = {category: min(points, CATEGORY_CAPS.get(category, 0)) for category, points in raw.items()}
    total = max(0, min(100, sum(capped.values())))
    level = level_for(total)
    return ScoreResult(total, level, RECOMMENDATIONS[level], capped, raw)
