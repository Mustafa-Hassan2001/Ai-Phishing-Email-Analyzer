"""Tests for the stretch features: batch mode and the optional VirusTotal lookup."""

import csv

import cli
from analyzer import virustotal
from analyzer.pipeline import analyze_file
from tests.conftest import SAMPLES


def test_batch_mode_writes_csv(tmp_path, capsys):
    folder = tmp_path / "mail"
    folder.mkdir()
    for sample in SAMPLES.glob("*.eml"):
        (folder / sample.name).write_bytes(sample.read_bytes())
    (folder / "broken.eml").write_bytes(b"")
    out = tmp_path / "summary.csv"

    assert cli.main([str(folder), "--csv", str(out)]) == 0
    rows = {row["file"]: row for row in csv.DictReader(out.open(encoding="utf-8"))}
    assert set(rows) == {p.name for p in SAMPLES.glob("*.eml")} | {"broken.eml"}
    assert rows["legitimate_newsletter.eml"]["level"] == "Low"
    assert int(rows["phishing_paypal.eml"]["score"]) >= 50
    assert "empty" in rows["broken.eml"]["error"]
    assert "Wrote" in capsys.readouterr().out


def test_batch_mode_empty_folder(tmp_path):
    assert cli.main([str(tmp_path)]) == 2


def test_virustotal_disabled_without_key(monkeypatch):
    monkeypatch.delenv(virustotal.ENV_VAR, raising=False)
    result = analyze_file(SAMPLES / "phishing_invoice_attachment.eml")
    assert virustotal.enrich(result, enabled=True) == []
    assert "virustotal" not in result.extra


def test_virustotal_disabled_unless_requested(monkeypatch):
    monkeypatch.setenv(virustotal.ENV_VAR, "dummy-key")

    def fail(*args, **kwargs):
        raise AssertionError("must not make network calls when disabled")

    monkeypatch.setattr(virustotal, "_get", fail)
    assert virustotal.enrich(analyze_file(SAMPLES / "phishing_paypal.eml"), enabled=False) == []


def test_virustotal_enrich_with_fake_api(monkeypatch):
    monkeypatch.setenv(virustotal.ENV_VAR, "dummy-key")
    calls = []

    def fake_get(path, key):
        calls.append(path)
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "harmless": 50}}}}

    monkeypatch.setattr(virustotal, "_get", fake_get)
    result = analyze_file(SAMPLES / "phishing_invoice_attachment.eml")
    lookups = virustotal.enrich(result, enabled=True)
    assert calls[0] == f"/files/{result.attachments[0].sha256}"
    assert calls[1].startswith("/urls/")
    assert lookups[0]["malicious"] == 3 and lookups[0]["status"] == "ok"
    assert result.extra["virustotal"] == lookups
    score_before = analyze_file(SAMPLES / "phishing_invoice_attachment.eml").score.total
    assert result.score.total == score_before  # informational only


def test_virustotal_url_id_has_no_padding():
    assert "=" not in virustotal.url_id("http://example.com/a")


def test_csv_safe_neutralizes_formulas():
    assert cli.csv_safe('=HYPERLINK("http://evil.example","x")').startswith("'=")
    assert cli.csv_safe("@SUM(1)") == "'@SUM(1)"
    assert cli.csv_safe("Normal subject") == "Normal subject"
    assert cli.csv_safe(42) == 42
