"""Tests for analyzer.domains and analyzer.urls."""

import pytest

from analyzer.domains import brands_in, is_ip_host, registrable_domain
from analyzer.parser import parse_email
from analyzer.urls import ExtractedURL, analyze_urls, check_url, extract_urls
from tests.conftest import make_eml


def flags(url: str, anchor: str = "") -> list[str]:
    finding, _ = check_url(ExtractedURL(url, "html", anchor))
    return finding.flags


# --- domains -----------------------------------------------------------------

@pytest.mark.parametrize(
    "host, expected",
    [
        ("www.paypal.com", "paypal.com"),
        ("login.secure.paypal.co.uk", "paypal.co.uk"),
        ("bbc.co.uk", "bbc.co.uk"),
        ("shop.example.com.au", "example.com.au"),
        ("PayPal.COM.", "paypal.com"),
        ("192.0.2.1", "192.0.2.1"),
        ("localhost", "localhost"),
        ("", ""),
    ],
)
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


@pytest.mark.parametrize("host", ["192.0.2.1", "[2001:db8::1]", "3232235777", "0xC0.0xA8.0.1"])
def test_is_ip_host_true(host):
    assert is_ip_host(host)


@pytest.mark.parametrize("host", ["example.com", "1password.com", ""])
def test_is_ip_host_false(host):
    assert not is_ip_host(host)


@pytest.mark.parametrize(
    "text, brand",
    [("paypa1-secure", "paypal"), ("m1crosoft", "microsoft"), ("rnicrosoft", "microsoft"),
     ("PAY-PAL", "paypal"), ("app1e-id", "apple"), ("amaz0n", "amazon"), ("d0cusign", "docusign")],
)
def test_brands_in_leetspeak(text, brand):
    assert brand in brands_in(text)


def test_brands_in_none():
    assert brands_in("example newsletter") == []


# --- URL heuristics ------------------------------------------------------------

def test_leetspeak_brand_impersonation():
    assert "brand_impersonation" in flags("https://paypa1-login.example/signin")


def test_real_brand_domain_not_flagged():
    assert flags("https://www.paypal.com/signin") == []


def test_co_uk_brand_domain_is_real():
    assert flags("https://www.amazon.co.uk/orders") == []


def test_co_uk_lookalike_is_flagged():
    # registrable domain is amazon-orders.co.uk, which Amazon does not own
    assert "brand_impersonation" in flags("https://www.amazon-orders.co.uk/login")


def test_brand_in_subdomain_of_other_domain():
    assert "brand_impersonation" in flags("https://paypal.com.account-check.example/")


def test_anchor_text_mismatch():
    assert "text_mismatch" in flags("https://evil.example/x", "https://www.paypal.com/signin")


def test_anchor_text_same_domain_ok():
    assert "text_mismatch" not in flags("https://www.example.org/a", "example.org")


def test_anchor_plain_words_ignored():
    assert "text_mismatch" not in flags("https://evil.example/x", "Click here to read more")


def test_ip_host_and_http():
    assert set(flags("http://192.0.2.45/reset")) >= {"ip_host", "http"}


def test_shortener():
    assert "shortener" in flags("https://bit.ly/abc123")


def test_punycode_without_hyphen_false_positive():
    result = flags("https://xn--pypal-4ve.com/")
    assert "punycode" in result
    assert "hyphens" not in result


def test_at_sign_and_suspicious_tld():
    result = flags("http://paypal.com@login-check.xyz/")
    assert {"at_sign", "suspicious_tld"} <= set(result)


def test_at_sign_in_path_not_flagged():
    assert "at_sign" not in flags("https://social.example/@alice")


def test_many_subdomains_long_url_and_hyphens():
    url = "https://a.b.c.secure-login-account-verify.example/" + "x" * 120
    assert {"subdomains", "long_url", "hyphens"} <= set(flags(url))


def test_malformed_url_does_not_crash():
    assert flags("http://[not-an-ip/") == []


# --- extraction ----------------------------------------------------------------

def test_extract_from_text_and_html_with_anchor():
    raw = make_eml(
        body="Visit https://text.example/a, or www.other.example.",
        html='<p><a href="https://html.example/b">Click</a><a href="mailto:x@example.com">mail</a></p>',
    )
    found = {(u.url, u.source, u.anchor_text) for u in extract_urls(parse_email(raw))}
    assert ("https://text.example/a", "text", "") in found
    assert ("http://www.other.example", "text", "") in found
    assert ("https://html.example/b", "html", "Click") in found
    assert all("mailto" not in u for u, _, _ in found)


def test_same_url_in_text_and_html_counted_once():
    raw = make_eml(body="http://192.0.2.9/x", html='<a href="http://192.0.2.9/x">here</a>')
    findings, indicators = analyze_urls(parse_email(raw))
    assert len(findings) == 1
    assert sum(1 for i in indicators if "raw IP" in i.description) == 1


def test_no_urls():
    findings, indicators = analyze_urls(parse_email(make_eml(body="No links here.")))
    assert findings == [] and indicators == []
