"""Headless smoke tests for the Streamlit UI using streamlit.testing.v1.AppTest.

Ollama is pointed at an unused local port so the tests never need a model
or network access.
"""

import socket

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

from tests.conftest import ROOT, SAMPLES  # noqa: E402

APP = str(ROOT / "app.py")


def _unused_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def new_app() -> AppTest:
    at = AppTest.from_file(APP, default_timeout=30)
    at.run()
    at.sidebar.text_input[0].set_value(f"http://127.0.0.1:{_unused_port()}")
    return at


def test_app_starts_without_input():
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception
    assert any("Upload an .eml" in i.value for i in at.info)


@pytest.mark.parametrize("sample", sorted(p.name for p in SAMPLES.glob("*.eml")))
def test_app_analyzes_every_sample(sample):
    at = new_app()
    at.sidebar.selectbox[0].select(sample).run()
    assert not at.exception
    assert not at.error
    assert len(at.tabs) == 6
    score = at.metric[0].value
    assert score.endswith("/100")
    total = int(score.split("/")[0])
    if sample.startswith("phishing"):
        assert total >= 50
    else:
        assert total < 25
    # AI tab falls back cleanly because nothing listens on the port.
    assert any("Offline template explanation" in c.value for c in at.caption)
    assert len(at.get("download_button")) == 2


def test_app_ollama_toggle_off():
    at = new_app()
    at.sidebar.toggle[0].set_value(False)
    at.sidebar.selectbox[0].select("phishing_paypal.eml").run()
    assert not at.exception
    assert any("Ollama disabled" in c.value for c in at.caption)


def test_app_upload_valid_eml():
    at = new_app()
    at.file_uploader[0].upload("mail.eml", (SAMPLES / "phishing_ip_link.eml").read_bytes()).run()
    assert not at.exception and not at.error
    assert at.metric[0].value.endswith("/100")


def test_app_bad_upload_shows_error_not_traceback():
    at = new_app()
    at.file_uploader[0].upload("bad.eml", b"\x89PNG\r\n\x1a\n\x00binary").run()
    assert not at.exception
    assert at.error and "Could not read this file as an email" in at.error[0].value


def test_app_never_renders_email_content_as_markdown():
    """Email-controlled strings (subject, From) must not reach st.markdown."""
    at = new_app()
    at.sidebar.selectbox[0].select("phishing_paypal.eml").run()
    markdown = "\n".join(m.value for m in at.markdown)
    assert "Urgent: Your account has been limited" not in markdown
    assert "paypa1-security" not in markdown
    assert any("Urgent: Your account has been limited" in t.value for t in at.text)


def test_run_analysis_helper_handles_errors():
    import importlib.util

    spec = importlib.util.spec_from_file_location("phish_app", APP)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # main() is guarded, so this only defines functions
    result, error = module.run_analysis(b"", "empty.eml")
    assert result is None and "empty" in error
    result, error = module.run_analysis((SAMPLES / "legitimate_newsletter.eml").read_bytes(), "n.eml")
    assert error is None and result.score.level == "Low"
