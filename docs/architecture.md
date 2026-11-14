# Architecture

## Data flow

```
                        ┌────────────────────────────── analyzer/pipeline.py: analyze(raw_bytes) ──────────────────────────────┐
 raw .eml bytes ──────► │ parser.parse_email ──► ParsedEmail                                                                  │
                        │                         │                                                                          │
                        │        ┌────────────────┼──────────────────┬─────────────────────┐                                 │
                        │        ▼                ▼                  ▼                     ▼                                 │
                        │  headers.analyze   urls.analyze     keywords.analyze    attachments.analyze                        │
                        │  (HeaderReport,    (URLFinding[],   (hits by tactic,    (AttachmentFinding[],                      │
                        │   Indicators)       Indicators)      Indicators)         Indicators)                               │
                        │        └────────────────┴──────────┬───────┴─────────────────────┘                                 │
                        │                                    ▼                                                               │
                        │                       scoring.score_indicators ──► ScoreResult (0-100, level, caps)               │
                        └───────────────────────────────────────┬────────────────────────────────────────────────────────────┘
                                                                ▼
                                                         AnalysisResult
                          ┌────────────────────┬────────────────┼──────────────────┬───────────────────────┐
                          ▼                    ▼                ▼                  ▼                       ▼
                    report.to_markdown   report.to_json   llm.explain         app.py (Streamlit)      cli.py
                    (defanged)                            (findings only)                              (+ batch CSV)
                                                                │
                                              Ollama /api/generate ──(fail)──► fallback template
```

1. **Parse.** `parser.parse_email` uses the stdlib `email` package (`policy.default`). It extracts
   decoded headers, the text and HTML bodies, and attachment metadata. Attachments are SHA-256-hashed
   in memory and their bytes are discarded. Malformed headers are recorded in `defects` instead of
   raising. Input that has no headers at all (a PNG, empty file) raises `EmailParseError`.
2. **Detect.** Four independent detectors each take the `ParsedEmail` and return
   `(details, list[Indicator])`. They don't know about each other or about scoring.
3. **Score.** `scoring.score_indicators` sums the points per category, caps each category, adds the
   capped values and clamps to 0–100. This is the single source of truth.
4. **Present.** Reports, the UI and the CLI all consume the same `AnalysisResult`.
5. **Explain.** `llm.explain` builds a prompt from the findings only, calls Ollama, and falls back to
   a template on any failure. It returns an `Explanation(text, source, model, error)`.

## Module responsibilities

| Module | Responsibility | Key functions |
|---|---|---|
| `parser.py` | `.eml` → `ParsedEmail`, attachment hashing, safe decoding | `parse_email`, `ParsedEmail.body_text` |
| `html_utils.py` | One `HTMLParser` that returns visible text and `(href, anchor text)` pairs; skips script/style | `html_to_text`, `extract_links` |
| `domains.py` | Registrable domain (co.uk-aware), IP detection (incl. decimal/hex), leetspeak variants, brand ownership | `registrable_domain`, `is_ip_host`, `brands_in`, `brand_owns_domain` |
| `indicators.py` | The `Indicator` dataclass and category names | `Indicator`, `dedupe` |
| `urls.py` | URL extraction from text + HTML; 11 URL heuristics | `extract_urls`, `check_url`, `analyze_urls` |
| `keywords.py` | Phrase matching per tactic, distinct-phrase counting, per-tactic caps | `find_phrases`, `analyze_keywords` |
| `headers.py` | SPF/DKIM/DMARC parsing, identity checks, Received chain | `parse_auth_results`, `parse_received_chain`, `analyze_headers` |
| `attachments.py` | Extension/MIME/RTLO checks on names only | `extensions`, `analyze_attachments` |
| `scoring.py` | Category caps, total, level, recommendation | `score_indicators`, `level_for` |
| `pipeline.py` | Wires everything together; size limit | `analyze`, `analyze_file` |
| `report.py` | JSON (raw values) and Markdown (defanged, escaped) | `to_json`, `to_markdown`, `defang` |
| `llm.py` | Prompt from findings, Ollama HTTP call, template fallback | `build_prompt`, `explain`, `fallback_explanation` |
| `virustotal.py` | Optional hash/URL reputation; off unless key + opt-in | `enrich` |
| `app.py` | Streamlit UI; untrusted text never rendered as Markdown/HTML | `run_analysis`, `main` |
| `cli.py` | Single-file reports, `--ai`, batch CSV, `--vt` | `main`, `batch_rows` |

## Scoring model

| Category | Cap | Example points |
|---|---|---|
| headers | 40 | SPF fail 20, DMARC fail 20, DKIM fail 15, display-name brand spoof 20, Reply-To mismatch 15, Return-Path mismatch 8, missing auth result 5 |
| urls | 40 | brand look-alike 25, link-text mismatch 20, IP host 20, punycode 15, `@` 15, shortener 10, abused TLD 10, http 5, long/deep/hyphens 5 |
| keywords | 30 | per tactic: urgency 4/hit (cap 12), credentials 6 (18), threats 5 (15), financial 4 (12), generic greeting 6 (6) |
| attachments | 45 | executable 30, RTLO 30, double extension 25, macro Office 25, executable MIME 25, HTML 20, archive 15 |

Levels: **Low** 0–24, **Medium** 25–49, **High** 50–74, **Critical** 75–100.

Because of the caps, keywords alone top out at 30 (Medium). To reach High, an email needs signals
from at least two categories, which matches how real phishing usually looks: a lure plus a delivery
mechanism plus weak sender identity.

## Design decisions

- **Standard library only for analysis.** It's easy to audit, there's no supply-chain surface in the core, and it runs anywhere.
- **Detectors return data, not scores.** Points live next to each rule (`POINTS` dicts), but
  aggregation lives only in `scoring.py`, so each piece can be explained and tested alone.
- **Distinct phrases, not occurrences.** Repeating "urgent" ten times counts once. A longer phrase
  absorbs a shorter one ("payment overdue" doesn't also count "overdue").
- **Dedup across MIME parts.** The same URL in the text and HTML alternatives is counted once.
- **Topmost Authentication-Results wins.** It was added by the final receiving server. Lower ones could
  have been injected by the sender.
