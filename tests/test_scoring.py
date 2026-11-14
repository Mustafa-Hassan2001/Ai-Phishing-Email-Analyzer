"""Tests for analyzer.scoring: caps, clamping and level boundaries."""

import pytest

from analyzer.indicators import ATTACHMENTS, HEADERS, KEYWORDS, URLS, Indicator
from analyzer.scoring import CATEGORY_CAPS, RECOMMENDATIONS, level_for, score_indicators


@pytest.mark.parametrize(
    "score, level",
    [(0, "Low"), (24, "Low"), (25, "Medium"), (49, "Medium"), (50, "High"), (74, "High"), (75, "Critical"), (100, "Critical")],
)
def test_level_boundaries(score, level):
    assert level_for(score) == level


@pytest.mark.parametrize("total, level", [(24, "Low"), (25, "Medium"), (49, "Medium"), (50, "High"), (74, "High"), (75, "Critical")])
def test_score_indicators_boundaries(total, level):
    # Split across categories so no cap interferes.
    a = min(total, 30)
    b = min(total - a, 30)
    parts = [Indicator(URLS, a, "a"), Indicator(HEADERS, b, "b"), Indicator(ATTACHMENTS, total - a - b, "c")]
    result = score_indicators(parts)
    assert result.total == total
    assert result.level == level
    assert result.recommendation == RECOMMENDATIONS[level]


def test_category_cap_limits_one_noisy_category():
    many = [Indicator(KEYWORDS, 10, f"k{i}") for i in range(20)]
    result = score_indicators(many)
    assert result.raw_category_points[KEYWORDS] == 200
    assert result.category_scores[KEYWORDS] == CATEGORY_CAPS[KEYWORDS]
    assert result.total == CATEGORY_CAPS[KEYWORDS]
    assert result.level != "Critical"


def test_total_is_clamped_to_100():
    indicators = [Indicator(c, 1000, c) for c in (HEADERS, URLS, KEYWORDS, ATTACHMENTS)]
    assert score_indicators(indicators).total == 100


def test_no_indicators_is_zero_low():
    result = score_indicators([])
    assert result.total == 0 and result.level == "Low"
    assert set(result.category_scores) == {HEADERS, URLS, KEYWORDS, ATTACHMENTS}


def test_negative_points_ignored():
    assert score_indicators([Indicator(URLS, -50, "weird")]).total == 0
