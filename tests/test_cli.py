"""Tests for cli.py (run in-process, no subprocess or network)."""

import json
import socket

import cli
from tests.conftest import SAMPLES


def _unused_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_cli_markdown(capsys):
    assert cli.main([str(SAMPLES / "phishing_paypal.eml")]) == 0
    out = capsys.readouterr().out
    assert "# Phishing Analysis Report" in out and "/100" in out


def test_cli_json(capsys):
    assert cli.main([str(SAMPLES / "legitimate_newsletter.eml"), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["score"]["level"] == "Low"


def test_cli_ai_fallback(capsys):
    args = [str(SAMPLES / "phishing_ip_link.eml"), "--ai", "--host", f"http://127.0.0.1:{_unused_port()}", "--timeout", "2"]
    assert cli.main(args) == 0
    captured = capsys.readouterr()
    assert "AI explanation (source: fallback)" in captured.out
    assert "hxxp://192[.]0[.]2[.]45" in captured.out
    assert "Ollama unavailable" in captured.err


def test_cli_missing_file(capsys):
    assert cli.main(["does-not-exist.eml"]) == 2
    assert "error:" in capsys.readouterr().err


def test_cli_garbage_file(tmp_path, capsys):
    junk = tmp_path / "junk.eml"
    junk.write_bytes(b"\x89PNG\r\n\x1a\n\x00binary")
    assert cli.main([str(junk)]) == 2
    assert "No email headers" in capsys.readouterr().err
