"""Tests for analyzer.parser and analyzer.html_utils."""

import hashlib

import pytest

from analyzer.html_utils import extract_links, html_to_text
from analyzer.parser import EmailParseError, parse_email
from tests.conftest import make_eml


def test_basic_headers_and_body():
    parsed = parse_email(make_eml())
    assert parsed.subject == "Lunch"
    assert parsed.from_display == "Alice"
    assert parsed.from_address == "alice@example.com"
    assert parsed.message_id == "<test-1@example.com>"
    assert "See you at lunch" in parsed.text_body
    assert parsed.attachments == []


def test_unicode_subject_is_decoded():
    parsed = parse_email(make_eml(headers={"Subject": "Rechnung über 500 € – dringend ✅"}))
    assert parsed.subject == "Rechnung über 500 € – dringend ✅"


def test_html_only_email_body_text_strips_tags():
    parsed = parse_email(make_eml(body="", html="<p>Hello <b>there</b></p><script>evil()</script>"))
    assert parsed.text_body == ""
    assert "<p>" in parsed.html_body
    assert parsed.body_text == "Hello there"


def test_empty_body_is_fine():
    parsed = parse_email(b"From: a@example.com\r\nSubject: empty\r\n\r\n")
    assert parsed.body_text == ""
    assert parsed.subject == "empty"


def test_attachment_metadata_and_sha256():
    payload = b"harmless dummy bytes"
    parsed = parse_email(make_eml(attachments=[("report.pdf", "application/pdf", payload)]))
    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.filename == "report.pdf"
    assert att.content_type == "application/pdf"
    assert att.size == len(payload)
    assert att.sha256 == hashlib.sha256(payload).hexdigest()


def test_malformed_headers_do_not_crash():
    raw = (
        b"From: =?utf-8?q?broken <<<@@@>>>\r\n"
        b"Subject: =?unknown-charset?B?!!!notbase64?=\r\n"
        b"Received: garbage without structure\r\n"
        b"Authentication-Results: ;;;;\r\n"
        b"\r\nbody\r\n"
    )
    parsed = parse_email(raw)
    assert "body" in parsed.body_text


@pytest.mark.parametrize("raw", [b"", b"   \n", b"\x89PNG\r\n\x1a\n\x00\x00binary"])
def test_rejects_non_email_input(raw):
    with pytest.raises(EmailParseError):
        parse_email(raw)


def test_rejects_non_bytes():
    with pytest.raises(EmailParseError):
        parse_email("not bytes")  # type: ignore[arg-type]


def test_html_utils_links_and_text():
    html = '<a href="https://evil.example/x">www.<b>paypal</b>.com</a> <form action="https://f.example/p"></form>'
    assert extract_links(html) == [("https://evil.example/x", "www.paypal.com"), ("https://f.example/p", "")]
    assert html_to_text(html) == "www. paypal .com"


def test_html_utils_tolerates_broken_html():
    assert html_to_text("<div><a href='x'>unclosed <<<") .startswith("unclosed")
