# Test cases

All sample emails are fake. Domains use reserved names (`.example`, `.test`, `example.org`,
`example.net`), IPs come from the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`), and the "executable" attachment is a harmless text file.

## Sample emails

| File | Scenario | Key signals it should trigger | Expected | Actual |
|---|---|---|---|---|
| `phishing_paypal.eml` | Fake PayPal "account limited" | Leetspeak look-alike `paypa1-security.example` (brand impersonation), link text `https://www.paypal.com/signin` → different host (mismatch), plain http, SPF **fail**, DMARC **fail**, DKIM none, Reply-To and Return-Path mismatch, display name "PayPal" from a non-PayPal domain, urgency/threat/credential phrases, "Dear Customer" | ≥ 50 (High/Critical) | **100 Critical** |
| `phishing_invoice_attachment.eml` | Fake overdue invoice | `Invoice_INV-20931.pdf.exe` (executable + double extension), `bit.ly` shortener, "Dear Customer", financial lures (invoice, payment overdue, wire transfer, outstanding balance), SPF **softfail**, no DKIM/DMARC | ≥ 50 (High/Critical) | **97 Critical** |
| `phishing_ip_link.eml` | "Password expires today" | Link to `http://192.0.2.45/...` (raw IP + http), display name "Microsoft 365 Security" from `mail-notify.example`, HTML-only body (tags stripped for keywords), credential/threat/urgency phrases, "Dear user", no SPF/DKIM/DMARC results | ≥ 50 (High/Critical) | **90 Critical** |
| `legitimate_newsletter.eml` | Ordinary newsletter | SPF/DKIM/DMARC **pass**, From / Reply-To / Return-Path all under `example.org`, https links whose text matches their domain, no pressure language, no attachments | < 25 (Low) | **0 Low** |

Check them yourself:

```bash
python cli.py samples/ --csv summary.csv
```

## What the automated tests cover

| Area | File | Examples |
|---|---|---|
| Parser | `tests/test_parser.py` | headers/body, unicode subject, HTML-only, empty body, malformed headers, attachment SHA-256, rejects empty/binary/non-bytes input |
| Domains & URLs | `tests/test_domains_urls.py` | co.uk / com.au registrable domains, decimal/hex IPs, leetspeak (`paypa1`, `m1crosoft`, `rnicrosoft`), co.uk look-alike, brand in a subdomain, anchor mismatch, IP, shortener, punycode (no false hyphen hit), `@` trick vs. `@` in a path, deep/long/hyphenated, malformed URL, text+HTML dedup |
| Keywords | `tests/test_detectors.py` | subject+body, HTML-only stripping, per-tactic cap, whole words (`insurgent` ≠ `urgent`), repeats count once, curly apostrophes, empty body |
| Headers | `tests/test_detectors.py` | pass/fail/softfail/missing, Received-SPF fallback, topmost AR wins, Reply-To / Return-Path mismatch, same registrable domain OK, brand display name (and real brand domain OK), email in display name, missing From / Message-ID, Received chain order |
| Attachments | `tests/test_detectors.py` | double extension, macro, archive, HTML, executable MIME with innocent name, RTLO, safe PDF, none |
| Scoring | `tests/test_scoring.py` | boundaries 24/25, 49/50, 74/75 (both `level_for` and the full scorer), category cap, clamp to 100, empty, negative points |
| End to end | `tests/test_end_to_end.py` | every sample in its range, expected signals per sample, sorted indicators, garbage and oversized input |
| Reports | `tests/test_end_to_end.py` | Markdown contains score/level and defanged URLs, JSON valid and body-free, explanation included, pipe/backtick/HTML escaping |
| LLM | `tests/test_end_to_end.py` | fallback on an unused port, invalid host scheme, mocked Ollama success, empty response → fallback, **prompt never contains the email body**, evidence sanitized |
| CLI | `tests/test_cli.py` | Markdown, JSON, `--ai` fallback (defanged), missing file, binary file |
| Extras | `tests/test_extras.py` | batch CSV incl. a broken file, empty folder, CSV formula injection, VirusTotal off without key / without opt-in, mocked VT, VT doesn't change score |
| UI | `tests/test_app.py` | AppTest: empty start, every sample via dropdown, Ollama toggle off, valid upload, **bad upload → `st.error`, no exception**, email text never rendered via Markdown |

Run everything (no network or Ollama required):

```bash
python -m pytest -v
```
