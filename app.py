"""Streamlit UI for the phishing analyzer.

Run with:  streamlit run app.py

SAFETY RULES FOR THIS UI
* Email content is untrusted. It is never passed to st.markdown/st.write
  (which would render Markdown links and images) and never rendered as HTML.
  Untrusted strings go through st.text, st.code or st.dataframe only.
* URLs are shown defanged (hxxp://evil[.]example) so they can't be clicked.
* Attachments are never opened; only their metadata and SHA-256 are shown.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

from analyzer import llm, virustotal
from analyzer.headers import MECHANISMS
from analyzer.keywords import TACTICS
from analyzer.parser import EmailParseError
from analyzer.pipeline import AnalysisResult, analyze
from analyzer.report import defang, to_json, to_markdown
from analyzer.scoring import CATEGORY_CAPS

SAMPLES_DIR = Path(__file__).resolve().parent / "samples"
MAX_UPLOAD_MB = 10
LEVEL_COLORS = {"Low": "green", "Medium": "yellow", "High": "orange", "Critical": "red"}
NO_SAMPLE = "(none)"


# --- analysis helpers (no Streamlit calls, easy to test) ------------------------

def run_analysis(raw: bytes, name: str) -> tuple[AnalysisResult | None, str | None]:
    """Analyze bytes and return (result, None) or (None, user-friendly error)."""
    if len(raw) > MAX_UPLOAD_MB * 1024 * 1024:
        return None, f"File is larger than {MAX_UPLOAD_MB} MB."
    try:
        return analyze(raw, source_name=name), None
    except EmailParseError as exc:
        return None, f"Could not read this file as an email: {exc}"
    except Exception as exc:  # noqa: BLE001 - the UI must never show a stack trace
        return None, f"Unexpected error while analyzing the file ({type(exc).__name__})."


@st.cache_data(show_spinner=False, max_entries=50)
def cached_analysis(raw: bytes, name: str) -> tuple[AnalysisResult | None, str | None]:
    return run_analysis(raw, name)


@st.cache_data(show_spinner=False, max_entries=50)
def cached_explanation(raw: bytes, name: str, host: str, model: str) -> llm.Explanation:
    result, _ = run_analysis(raw, name)
    return llm.explain(result, host=host, model=model)


def list_samples() -> list[str]:
    return sorted(p.name for p in SAMPLES_DIR.glob("*.eml")) if SAMPLES_DIR.is_dir() else []


def labeled_text(label: str, value: str) -> None:
    """Show untrusted text safely (no Markdown/HTML rendering)."""
    st.text(f"{label}: {value or '(none)'}")


# --- page sections ------------------------------------------------------------

def sidebar() -> dict:
    st.sidebar.header("Settings")
    use_ollama = st.sidebar.toggle("Use Ollama", value=True, help="Off = always use the offline template explanation.")
    host = st.sidebar.text_input("Ollama host", value=llm.DEFAULT_HOST)
    model = st.sidebar.text_input("Ollama model", value=llm.DEFAULT_MODEL)
    sample = st.sidebar.selectbox("Load sample email", [NO_SAMPLE, *list_samples()])
    use_vt = False
    if virustotal.is_configured():  # only offered when VT_API_KEY is set
        use_vt = st.sidebar.checkbox("VirusTotal lookups", value=False,
                                     help="Sends attachment hashes and URLs (never files) to VirusTotal.")
    st.sidebar.caption("The risk score is rule-based. The AI only explains it and can't change it.")
    return {"use_ollama": use_ollama, "host": host, "model": model, "sample": sample, "use_vt": use_vt}


def show_score(result: AnalysisResult) -> None:
    score = result.score
    col_score, col_level = st.columns([1, 2])
    col_score.metric("Risk score", f"{score.total}/100")
    with col_level:
        # Safe to use Markdown here: level/colour come from our own constants, not the email.
        st.markdown(f"### :{LEVEL_COLORS[score.level]}-background[{score.level} risk]")
        st.text(score.recommendation)
    st.progress(score.total / 100)


def tab_summary(result: AnalysisResult) -> None:
    parsed = result.parsed
    labeled_text("Subject", parsed.subject)
    labeled_text("From", parsed.from_header)
    labeled_text("Date", parsed.date)
    st.subheader("Indicators")
    if result.indicators:
        st.dataframe(
            pd.DataFrame([i.to_dict() for i in result.indicators])[["points", "category", "description", "evidence"]]
            .assign(evidence=lambda df: df["evidence"].map(defang)),
            hide_index=True,
            width="stretch",
        )
    else:
        st.success("No suspicious indicators found.")
    st.subheader("Score by category")
    rows = [
        {"category": c, "raw points": result.score.raw_category_points[c], "capped score": s, "cap": CATEGORY_CAPS[c]}
        for c, s in result.score.category_scores.items()
    ]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    if result.extra.get("virustotal"):
        st.subheader("VirusTotal (informational, does not change the score)")
        st.dataframe(pd.DataFrame(result.extra["virustotal"]).assign(target=lambda df: df["target"].map(defang)),
                     hide_index=True, width="stretch")
    if parsed.defects:
        with st.expander("Parser warnings"):
            st.text("\n".join(parsed.defects))


def tab_urls(result: AnalysisResult) -> None:
    if not result.urls:
        st.info("No URLs found.")
        return
    st.caption("URLs are defanged (hxxp, [.]) so they can't be clicked by accident.")
    rows = [
        {"url": defang(u.url), "anchor text": defang(u.anchor_text), "domain": defang(u.registrable_domain),
         "source": u.source, "flags": ", ".join(u.flags) or "-"}
        for u in result.urls
    ]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


def tab_keywords(result: AnalysisResult) -> None:
    if not result.keyword_hits:
        st.info("No social-engineering phrases found.")
        return
    for tactic in TACTICS:
        phrases = result.keyword_hits.get(tactic.name)
        if phrases:
            st.text(f"{tactic.label}: {', '.join(phrases)}")


def tab_headers(result: AnalysisResult) -> None:
    hdr = result.headers
    labeled_text("From", hdr.from_header)
    labeled_text("Reply-To", hdr.reply_to)
    labeled_text("Return-Path", hdr.return_path)
    labeled_text("Message-ID", hdr.message_id)
    st.subheader("Authentication")
    cols = st.columns(len(MECHANISMS))
    for col, mechanism in zip(cols, MECHANISMS):
        col.metric(mechanism.upper(), hdr.auth.get(mechanism, "missing"))
    st.subheader("Received chain (oldest hop first)")
    if hdr.received:
        st.dataframe(
            pd.DataFrame([{"hop": n, "from": h.from_host, "by": h.by_host, "date": h.date} for n, h in enumerate(hdr.received, 1)]),
            hide_index=True,
            width="stretch",
        )
    else:
        st.info("No Received headers.")
    with st.expander("All raw headers"):
        st.code("\n".join(f"{k}: {v}" for k, v in result.parsed.headers), language=None, wrap_lines=True)


def tab_attachments(result: AnalysisResult) -> None:
    st.caption("Attachments are never opened or executed. Only metadata and hashes are shown.")
    if not result.attachments:
        st.info("No attachments.")
        return
    rows = [
        {"filename": a.filename, "content type": a.content_type, "size (bytes)": a.size,
         "sha256": a.sha256, "flags": ", ".join(a.flags) or "-"}
        for a in result.attachments
    ]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


def get_explanation(raw: bytes, name: str, result: AnalysisResult, settings: dict) -> llm.Explanation:
    if not settings["use_ollama"]:
        return llm.Explanation(llm.fallback_explanation(result), "fallback", error="Ollama disabled in the sidebar")
    with st.spinner("Asking the local model for an explanation..."):
        return cached_explanation(raw, name, settings["host"], settings["model"])


def tab_ai(explanation: llm.Explanation) -> None:
    if explanation.source == "ollama":
        st.caption(f"Generated locally by Ollama ({explanation.model}) from the findings only, never the email body.")
    else:
        st.caption(f"Offline template explanation. Reason: {explanation.error or 'Ollama unavailable'}")
    st.code(explanation.text, language=None, wrap_lines=True)


# --- main -------------------------------------------------------------------------

def main() -> None:
    st.set_page_config(page_title="Phishing Email Analyzer", page_icon="🎣", layout="wide")
    st.title("Phishing Email Analyzer")
    st.caption("Upload a suspicious .eml file. Nothing leaves this machine; the AI explanation uses a local model.")
    settings = sidebar()

    upload = st.file_uploader("Upload an .eml file", type=["eml"])
    if upload is not None:
        raw, name = upload.getvalue(), upload.name
    elif settings["sample"] != NO_SAMPLE:
        raw, name = (SAMPLES_DIR / settings["sample"]).read_bytes(), settings["sample"]
    else:
        st.info("Upload an .eml file or pick a sample in the sidebar to begin.")
        return

    result, error = cached_analysis(raw, name)
    if error or result is None:
        st.error(error or "Analysis failed.")
        return

    if settings["use_vt"]:
        with st.spinner("Querying VirusTotal..."):
            virustotal.enrich(result, enabled=True)

    show_score(result)
    tabs = st.tabs(["Summary", "URLs", "Keywords", "Headers", "Attachments", "AI explanation"])
    with tabs[0]:
        tab_summary(result)
    with tabs[1]:
        tab_urls(result)
    with tabs[2]:
        tab_keywords(result)
    with tabs[3]:
        tab_headers(result)
    with tabs[4]:
        tab_attachments(result)
    with tabs[5]:
        explanation = get_explanation(raw, name, result, settings)
        tab_ai(explanation)

    stem = Path(name).stem or "report"
    col_md, col_json = st.columns(2)
    col_md.download_button("Download Markdown report", to_markdown(result, explanation), f"{stem}_report.md", "text/markdown")
    col_json.download_button("Download JSON report", to_json(result, explanation), f"{stem}_report.json", "application/json")


if __name__ == "__main__":  # Streamlit runs this file as __main__
    main()
