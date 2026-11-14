"""Social-engineering phrase detection.

Phrases are grouped by the psychological tactic they use. Each *distinct*
phrase counts once (repeating "urgent" ten times is still one hit), and each
tactic has a cap so a wordy email can't run up the score on its own.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .indicators import KEYWORDS, Indicator
from .parser import ParsedEmail


@dataclass(frozen=True)
class Tactic:
    """A group of phrases that share a social-engineering tactic."""

    name: str
    label: str
    points_per_hit: int
    cap: int
    phrases: tuple[str, ...]


TACTICS: tuple[Tactic, ...] = (
    Tactic(
        "urgency", "Urgency / time pressure", 4, 12,
        ("urgent", "immediately", "immediate action", "action required", "within 24 hours",
         "within 48 hours", "expires today", "will expire", "as soon as possible", "final notice",
         "last warning", "act now", "right away", "time sensitive", "time-sensitive", "today only"),
    ),
    Tactic(
        "credential_request", "Credential / personal data request", 6, 18,
        ("verify your account", "verify your identity", "confirm your identity", "confirm your password",
         "verify your password", "update your password", "reset your password", "enter your password",
         "login credentials", "confirm your credentials", "sign in to verify", "validate your account",
         "update your payment information", "update your billing", "social security number",
         "confirm your account", "keep your password"),
    ),
    Tactic(
        "threat", "Threat / negative consequence", 5, 15,
        ("suspended", "will be suspended", "will be locked", "has been locked", "permanently deleted",
         "will be closed", "unauthorized access", "unusual activity", "suspicious activity",
         "legal action", "terminated", "restricted", "deactivated", "lose access"),
    ),
    Tactic(
        "financial_lure", "Financial lure", 4, 12,
        ("invoice", "payment overdue", "overdue", "wire transfer", "gift card", "refund", "bank account",
         "outstanding balance", "payment failed", "unpaid", "bitcoin", "you have won", "lottery",
         "claim your reward", "claim your prize"),
    ),
    Tactic(
        "generic_greeting", "Generic greeting", 6, 6,
        ("dear customer", "dear user", "dear client", "dear valued customer", "dear account holder",
         "dear member", "dear sir/madam", "dear sir or madam", "dear email user", "dear account owner",
         "hello user"),
    ),
)


def _phrase_pattern(phrase: str) -> re.Pattern[str]:
    """Whole-word, whitespace-tolerant pattern for a phrase."""
    body = r"\s+".join(re.escape(word) for word in phrase.split())
    return re.compile(rf"(?<!\w){body}(?!\w)")


_PATTERNS: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    t.name: [(p, _phrase_pattern(p)) for p in t.phrases] for t in TACTICS
}


def normalize_text(text: str) -> str:
    """Lowercase, unify apostrophes, collapse whitespace."""
    text = text.replace("’", "'").replace("‘", "'").lower()
    return " ".join(text.split())


def find_phrases(text: str) -> dict[str, list[str]]:
    """Return {tactic_name: [matched phrases]} for tactics with at least one hit."""
    text = normalize_text(text)
    hits: dict[str, list[str]] = {}
    for tactic in TACTICS:
        matched = [phrase for phrase, pattern in _PATTERNS[tactic.name] if pattern.search(text)]
        # "payment overdue" already covers "overdue": don't count the shorter phrase twice.
        matched = [p for p in matched if not any(p != other and p in other for other in matched)]
        if matched:
            hits[tactic.name] = matched
    return hits


def analyze_keywords(parsed: ParsedEmail) -> tuple[dict[str, list[str]], list[Indicator]]:
    """Search subject + body (tags stripped for HTML-only mail)."""
    hits = find_phrases(f"{parsed.subject}\n{parsed.body_text}")
    indicators: list[Indicator] = []
    for tactic in TACTICS:
        phrases = hits.get(tactic.name)
        if not phrases:
            continue
        points = min(len(phrases) * tactic.points_per_hit, tactic.cap)
        indicators.append(
            Indicator(
                KEYWORDS,
                points,
                f"{tactic.label} language ({len(phrases)} phrase{'s' if len(phrases) > 1 else ''})",
                ", ".join(f'"{p}"' for p in phrases),
            )
        )
    return hits, indicators
