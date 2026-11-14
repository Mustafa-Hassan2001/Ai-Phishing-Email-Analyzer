"""Command-line interface.

Examples:
    python cli.py samples/phishing_paypal.eml            # Markdown report
    python cli.py samples/phishing_paypal.eml --json     # JSON report
    python cli.py samples/phishing_paypal.eml --ai       # add an AI explanation (Ollama or fallback)
    python cli.py samples/ --csv summary.csv             # batch: every .eml in a folder -> CSV
    VT_API_KEY=... python cli.py mail.eml --vt           # optional VirusTotal hash/URL lookups

Exit codes: 0 = analyzed, 2 = input error.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from analyzer import llm, virustotal
from analyzer.parser import EmailParseError
from analyzer.pipeline import analyze_file
from analyzer.report import to_json, to_markdown

CSV_FIELDS = ["file", "score", "level", "indicators", "top_finding", "subject", "from", "attachments", "error"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze suspicious .eml files for phishing indicators.")
    parser.add_argument("path", help="an .eml file, or a folder of .eml files (batch mode)")
    parser.add_argument("--json", action="store_true", help="print the JSON report instead of Markdown")
    parser.add_argument("--ai", action="store_true", help="add a plain-English explanation (Ollama, else template)")
    parser.add_argument("--host", default=llm.DEFAULT_HOST, help=f"Ollama URL (default {llm.DEFAULT_HOST})")
    parser.add_argument("--model", default=llm.DEFAULT_MODEL, help=f"Ollama model (default {llm.DEFAULT_MODEL})")
    parser.add_argument("--timeout", type=float, default=llm.DEFAULT_TIMEOUT, help="Ollama timeout in seconds")
    parser.add_argument("--csv", metavar="OUT", help="batch mode: write the summary to this CSV file")
    parser.add_argument("--vt", action="store_true", help=f"VirusTotal lookups (needs ${virustotal.ENV_VAR}; off by default)")
    return parser


def run_single(args: argparse.Namespace) -> int:
    """Analyze one file and print its report."""
    result = analyze_file(args.path)
    if args.vt:
        if not virustotal.is_configured():
            print(f"[info] --vt ignored: set {virustotal.ENV_VAR} to enable VirusTotal lookups.", file=sys.stderr)
        virustotal.enrich(result, enabled=True)
    explanation = llm.explain(result, args.host, args.model, args.timeout) if args.ai else None
    if explanation is not None and explanation.source == "fallback":
        print(f"[info] Ollama unavailable ({explanation.error}); using template explanation.", file=sys.stderr)
    print(to_json(result, explanation) if args.json else to_markdown(result, explanation))
    return 0


def csv_safe(value: object) -> object:
    """Stop CSV/formula injection: a subject like '=HYPERLINK(...)' must not run in Excel."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def batch_rows(folder: Path) -> list[dict]:
    """Analyze every .eml in a folder. Bad files become rows with an error."""
    rows: list[dict] = []
    for path in sorted(folder.glob("*.eml")):
        row = dict.fromkeys(CSV_FIELDS, "")
        row["file"] = path.name
        try:
            result = analyze_file(path)
        except (EmailParseError, OSError) as exc:
            row["error"] = str(exc)
            rows.append(row)
            continue
        row.update(
            score=result.score.total,
            level=result.score.level,
            indicators=len(result.indicators),
            top_finding=result.indicators[0].description if result.indicators else "",
            subject=result.parsed.subject,
            attachments=len(result.attachments),
        )
        row["from"] = result.parsed.from_header
        rows.append(row)
    return rows


def run_batch(args: argparse.Namespace) -> int:
    """Analyze a folder and print a table (and optionally write a CSV)."""
    rows = batch_rows(Path(args.path))
    if not rows:
        raise EmailParseError(f"No .eml files found in {args.path}")
    for row in rows:
        status = row["error"] or f"{row['score']:>3}/100 {row['level']:<8} {row['top_finding']}"
        print(f"{row['file']:<40} {status}")
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
            writer.writeheader()
            writer.writerows({k: csv_safe(v) for k, v in row.items()} for row in rows)
        print(f"\nWrote {len(rows)} rows to {args.csv}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    path = Path(args.path)
    try:
        if path.is_dir():
            return run_batch(args)
        if not path.is_file():
            raise EmailParseError(f"No such file or folder: {path}")
        return run_single(args)
    except (EmailParseError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
