"""Tests for the keyword, header and attachment detectors."""

from analyzer.attachments import analyze_attachments, extensions
from analyzer.headers import analyze_headers, parse_auth_results
from analyzer.keywords import TACTICS, analyze_keywords, find_phrases
from analyzer.parser import parse_email
from tests.conftest import make_eml

AR_PASS = "mx.example.net; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass"


def descriptions(indicators) -> str:
    return " | ".join(i.description for i in indicators)


# --- keywords -------------------------------------------------------------------

def test_keywords_found_in_subject_and_body():
    raw = make_eml(headers={"Subject": "URGENT: action required"}, body="Dear customer, verify your account.")
    hits, indicators = analyze_keywords(parse_email(raw))
    assert "urgent" in hits["urgency"] and "action required" in hits["urgency"]
    assert hits["credential_request"] == ["verify your account"]
    assert hits["generic_greeting"] == ["dear customer"]
    assert len(indicators) == 3


def test_keywords_html_only_tags_stripped():
    raw = make_eml(body="", html="<p>Please <b>verify</b> <i>your</i> account</p>")
    hits, _ = analyze_keywords(parse_email(raw))
    assert hits.get("credential_request") == ["verify your account"]


def test_keywords_respect_cap_and_whole_words():
    urgency = next(t for t in TACTICS if t.name == "urgency")
    text = " ".join(urgency.phrases)
    _, indicators = analyze_keywords(parse_email(make_eml(body=text)))
    urgency_ind = next(i for i in indicators if "Urgency" in i.description)
    assert urgency_ind.points == urgency.cap
    # "insurgent" must not match "urgent"
    assert "urgency" not in find_phrases("The insurgents left.")


def test_keywords_repeated_phrase_counts_once():
    _, indicators = analyze_keywords(parse_email(make_eml(body="urgent urgent urgent urgent", headers={"Subject": "hi"})))
    assert indicators[0].points == 4


def test_keywords_empty_body():
    hits, indicators = analyze_keywords(parse_email(b"From: a@example.com\r\nSubject: hi\r\n\r\n"))
    assert hits == {} and indicators == []


def test_keywords_unicode_apostrophe():
    assert "threat" in find_phrases("You’ll lose access tomorrow")


# --- headers ---------------------------------------------------------------------

def test_auth_results_pass_clean():
    raw = make_eml(headers={"Authentication-Results": AR_PASS})
    report, indicators = analyze_headers(parse_email(raw))
    assert report.auth == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert indicators == []


def test_auth_fail_softfail_and_missing():
    raw = make_eml(headers={"Authentication-Results": "mx.example.net; spf=softfail; dmarc=fail"})
    report, indicators = analyze_headers(parse_email(raw))
    assert report.auth == {"spf": "softfail", "dkim": "missing", "dmarc": "fail"}
    text = descriptions(indicators)
    assert "SPF check returned 'softfail'" in text
    assert "No DKIM result" in text
    assert "DMARC check returned 'fail'" in text


def test_received_spf_fallback():
    raw = make_eml(headers={"Received-SPF": "fail (domain does not designate sender) client-ip=192.0.2.1"})
    assert parse_auth_results(parse_email(raw))["spf"] == "fail"


def test_topmost_auth_results_wins():
    raw = (
        b"Authentication-Results: mx.example.net; spf=fail\r\n"
        b"Authentication-Results: forged.example; spf=pass\r\n"
        b"From: a@example.com\r\n\r\nbody\r\n"
    )
    assert parse_auth_results(parse_email(raw))["spf"] == "fail"


def test_reply_to_and_return_path_mismatch():
    raw = make_eml(headers={"Authentication-Results": AR_PASS,
                            "Reply-To": "help@other.example", "Return-Path": "<b@bounce.example>"})
    _, indicators = analyze_headers(parse_email(raw))
    text = descriptions(indicators)
    assert "Reply-To" in text and "Return-Path" in text


def test_same_registrable_domain_is_not_mismatch():
    raw = make_eml(headers={"Authentication-Results": AR_PASS, "From": "News <news@mail.example.com>",
                            "Reply-To": "help@example.com", "Return-Path": "<bounce@bounces.example.com>"})
    _, indicators = analyze_headers(parse_email(raw))
    assert indicators == []


def test_display_name_brand_spoof():
    raw = make_eml(headers={"Authentication-Results": AR_PASS, "From": "Micr0soft Support <help@desk.example>"})
    _, indicators = analyze_headers(parse_email(raw))
    assert "claims to be 'microsoft'" in descriptions(indicators)


def test_display_name_brand_real_domain_ok():
    raw = make_eml(headers={"Authentication-Results": AR_PASS, "From": "PayPal <service@paypal.com>"})
    _, indicators = analyze_headers(parse_email(raw))
    assert indicators == []


def test_display_name_contains_other_email():
    raw = make_eml(headers={"Authentication-Results": AR_PASS, "From": '"security@bank.example" <x@attacker.example>'})
    _, indicators = analyze_headers(parse_email(raw))
    assert "different email address" in descriptions(indicators)


def test_missing_from_and_message_id():
    raw = b"Subject: hi\r\nTo: b@example.net\r\n\r\nbody\r\n"
    report, indicators = analyze_headers(parse_email(raw))
    text = descriptions(indicators)
    assert "From header is missing" in text and "Message-ID header is missing" in text
    assert report.auth["spf"] == "missing"


def test_received_chain_oldest_first():
    raw = (
        b"Received: from mx2.example.net (mx2.example.net [192.0.2.2]) by inbox.example.net; Fri, 13 Nov 2026 10:00:02 +0000\r\n"
        b"Received: from sender.example (unknown [192.0.2.1]) by mx2.example.net; Fri, 13 Nov 2026 10:00:01 +0000\r\n"
        b"From: a@example.com\r\n\r\nbody\r\n"
    )
    _report, _ = analyze_headers(parse_email(raw))
    hops = _report.received
    assert [h.by_host for h in hops] == ["mx2.example.net", "inbox.example.net"]
    assert hops[0].from_host.startswith("sender.example")
    assert hops[0].date.endswith("+0000")


# --- attachments -----------------------------------------------------------------

def att_flags(filename: str, mime: str = "application/octet-stream") -> list[str]:
    raw = make_eml(attachments=[(filename, mime, b"dummy")])
    findings, _ = analyze_attachments(parse_email(raw))
    return findings[0].flags


def test_extensions_helper():
    assert extensions("Invoice.PDF .exe") == ["pdf", "exe"]
    assert extensions("README") == []


def test_double_extension_executable():
    assert set(att_flags("invoice.pdf.exe")) == {"executable", "double_extension"}


def test_macro_archive_html():
    assert att_flags("budget.xlsm") == ["macro_office"]
    assert att_flags("docs.zip") == ["archive"]
    assert att_flags("login.html") == ["html_attachment"]


def test_executable_mime_with_innocent_name():
    assert att_flags("photo.jpg", "application/x-msdownload") == ["executable_mime"]


def test_rtlo_filename():
    assert "rtlo" in att_flags("invoice‮fdp.exe")


def test_safe_attachment_and_none():
    assert att_flags("report.pdf", "application/pdf") == []
    findings, indicators = analyze_attachments(parse_email(make_eml()))
    assert findings == [] and indicators == []


def test_attachment_finding_records_hash_and_size():
    raw = make_eml(attachments=[("a.txt", "text/plain", b"abc")])
    findings, _ = analyze_attachments(parse_email(raw))
    assert findings[0].size == 3
    assert findings[0].sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
