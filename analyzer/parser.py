""".eml parsing: raw bytes -> ParsedEmail.

Uses only the standard library `email` package. Attachments are hashed
(SHA-256) in memory and then discarded: they are never written to disk,
opened, or executed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from email import message_from_bytes, policy
from email.message import Message
from email.utils import parseaddr

from .html_utils import html_to_text


class EmailParseError(ValueError):
    """Raised when the input is not something we can treat as an email."""


@dataclass
class Attachment:
    """Metadata about one attachment. The content itself is not kept."""

    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass
class ParsedEmail:
    """The parts of an email the detectors care about."""

    subject: str = ""
    from_header: str = ""
    from_display: str = ""
    from_address: str = ""
    to: str = ""
    date: str = ""
    reply_to: str = ""
    return_path: str = ""
    message_id: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    text_body: str = ""
    html_body: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    defects: list[str] = field(default_factory=list)

    def get_all(self, name: str) -> list[str]:
        """Return every value of a header (case-insensitive), in file order."""
        wanted = name.lower()
        return [value for key, value in self.headers if key.lower() == wanted]

    @property
    def body_text(self) -> str:
        """Plain-text body, or the HTML body with tags stripped if HTML-only."""
        if self.text_body.strip():
            return self.text_body
        return html_to_text(self.html_body)


def _header_value(msg: Message, name: str, defects: list[str]) -> str:
    """Read one header as a decoded string, tolerating malformed values."""
    try:
        value = msg.get(name)
    except Exception as exc:  # noqa: BLE001 - malformed headers are expected input
        defects.append(f"Could not parse {name} header: {exc}")
        return ""
    return "" if value is None else " ".join(str(value).split())


def _all_headers(msg: Message, defects: list[str]) -> list[tuple[str, str]]:
    """Return all headers as (name, value) strings in file order."""
    headers: list[tuple[str, str]] = []
    for name, raw in msg.raw_items():
        try:
            value = str(msg.policy.header_factory(name, raw))
        except Exception:  # noqa: BLE001
            defects.append(f"Malformed {name} header kept as raw text")
            value = str(raw)
        headers.append((name, " ".join(value.split())))
    return headers


def _decode_text(part: Message) -> str:
    """Decode a text part to str, falling back to lenient UTF-8."""
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
    except Exception:  # noqa: BLE001 - unknown charsets, bad encodings
        pass
    payload = part.get_payload(decode=True) or b""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _safe_filename(part: Message) -> str:
    try:
        return part.get_filename() or ""
    except Exception:  # noqa: BLE001
        return "(undecodable filename)"


def parse_email(raw: bytes) -> ParsedEmail:
    """Parse raw .eml bytes into a ParsedEmail.

    Raises:
        EmailParseError: if the input is empty or has no email headers.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise EmailParseError("Expected raw bytes from an .eml file.")
    if not raw.strip():
        raise EmailParseError("The file is empty.")

    try:
        msg = message_from_bytes(bytes(raw), policy=policy.default)
    except Exception as exc:  # noqa: BLE001
        raise EmailParseError(f"Could not parse the file as an email: {exc}") from exc
    if not msg.keys():
        raise EmailParseError("No email headers found. Is this really an .eml file?")

    parsed = ParsedEmail()
    defects = parsed.defects
    parsed.headers = _all_headers(msg, defects)
    parsed.subject = _header_value(msg, "Subject", defects)
    parsed.from_header = _header_value(msg, "From", defects)
    parsed.to = _header_value(msg, "To", defects)
    parsed.date = _header_value(msg, "Date", defects)
    parsed.reply_to = _header_value(msg, "Reply-To", defects)
    parsed.return_path = _header_value(msg, "Return-Path", defects)
    parsed.message_id = _header_value(msg, "Message-ID", defects)
    parsed.from_display, parsed.from_address = parseaddr(parsed.from_header)
    parsed.from_address = parsed.from_address.lower()

    text_parts: list[str] = []
    html_parts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        filename = _safe_filename(part)
        disposition = part.get_content_disposition()
        is_body_text = content_type in ("text/plain", "text/html") and not filename and disposition != "attachment"

        if is_body_text:
            target = text_parts if content_type == "text/plain" else html_parts
            target.append(_decode_text(part))
            continue

        # Anything else is treated as an attachment: hash it, keep metadata only.
        payload = part.get_payload(decode=True) or b""
        parsed.attachments.append(
            Attachment(
                filename=filename or "(unnamed)",
                content_type=content_type,
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        )

    parsed.text_body = "\n".join(text_parts)
    parsed.html_body = "\n".join(html_parts)
    defects.extend(type(defect).__name__ for defect in getattr(msg, "defects", []))
    return parsed
