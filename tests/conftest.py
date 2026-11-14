"""Shared test helpers: build small .eml messages in memory."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"

# Make `import analyzer` work no matter where pytest is started from.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def make_eml(
    headers: dict[str, str] | None = None,
    body: str = "Hello,\nSee you at lunch.\n",
    html: str | None = None,
    attachments: list[tuple[str, str, bytes]] | None = None,
) -> bytes:
    """Build an .eml as bytes using the stdlib EmailMessage builder.

    attachments: list of (filename, mime type "main/sub", payload bytes).
    Pass body="" together with html="..." for an HTML-only email.
    """
    from email.message import EmailMessage

    msg = EmailMessage()
    default_headers = {
        "From": "Alice <alice@example.com>",
        "To": "bob@example.net",
        "Subject": "Lunch",
        "Message-ID": "<test-1@example.com>",
        "Date": "Fri, 13 Nov 2026 10:00:00 +0000",
    }
    for name, value in {**default_headers, **(headers or {})}.items():
        if value is not None:
            msg[name] = value

    if html is not None and not body:
        msg.set_content(html, subtype="html")
    else:
        msg.set_content(body)
        if html is not None:
            msg.add_alternative(html, subtype="html")

    for filename, mime, payload in attachments or []:
        maintype, subtype = mime.split("/", 1)
        msg.add_attachment(payload, maintype=maintype, subtype=subtype, filename=filename)
    return msg.as_bytes()


@pytest.fixture
def eml():
    """Fixture form of make_eml for tests that prefer injection."""
    return make_eml
