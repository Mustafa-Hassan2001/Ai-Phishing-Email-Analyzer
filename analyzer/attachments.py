"""Dangerous attachment checks.

SAFETY: this module only looks at the filename and declared content type that
the parser recorded. The attachment bytes were hashed by the parser and then
dropped; nothing here opens, extracts, or executes anything.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .indicators import ATTACHMENTS, Indicator
from .parser import ParsedEmail

EXECUTABLE_EXTS = frozenset(
    {"exe", "scr", "com", "pif", "bat", "cmd", "msi", "js", "jse", "vbs", "vbe", "wsf", "wsh",
     "ps1", "hta", "jar", "lnk", "cpl", "reg", "dll", "msc", "appx", "sh"}
)
MACRO_EXTS = frozenset({"docm", "dotm", "xlsm", "xltm", "xlsb", "xlam", "pptm", "potm", "ppam", "ppsm"})
ARCHIVE_EXTS = frozenset({"zip", "rar", "7z", "gz", "tgz", "tar", "ace", "cab", "iso", "img", "arj", "lzh"})
HTML_EXTS = frozenset({"html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml"})
# Extensions attackers put *before* the real one to look harmless.
DECOY_EXTS = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "csv", "rtf"})
EXECUTABLE_MIME = frozenset(
    {"application/x-msdownload", "application/x-msdos-program", "application/x-dosexec",
     "application/x-executable", "application/x-sh", "application/hta", "application/java-archive",
     "application/x-ms-shortcut", "application/vnd.microsoft.portable-executable"}
)
RTLO = "‮"  # Right-to-left override: makes "invoice‮fdp.exe" display as "invoiceexe.pdf"

POINTS: dict[str, int] = {
    "executable": 30,
    "double_extension": 25,
    "macro_office": 25,
    "archive": 15,
    "html_attachment": 20,
    "executable_mime": 25,
    "rtlo": 30,
}


@dataclass
class AttachmentFinding:
    """Attachment metadata plus the names of the rules it triggered."""

    filename: str
    content_type: str
    size: int
    sha256: str
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def extensions(filename: str) -> list[str]:
    """Return lowercase extensions, e.g. 'Invoice.PDF .exe' -> ['pdf', 'exe']."""
    name = filename.replace(RTLO, "").strip().rstrip(". ").lower()
    return [part.strip() for part in name.split(".")[1:] if part.strip()]


def analyze_attachments(parsed: ParsedEmail) -> tuple[list[AttachmentFinding], list[Indicator]]:
    """Check every attachment's name and type. Returns (findings, indicators)."""
    findings: list[AttachmentFinding] = []
    indicators: list[Indicator] = []

    for att in parsed.attachments:
        finding = AttachmentFinding(att.filename, att.content_type, att.size, att.sha256)
        exts = extensions(att.filename)
        last = exts[-1] if exts else ""

        def flag(rule: str, description: str) -> None:
            finding.flags.append(rule)
            indicators.append(Indicator(ATTACHMENTS, POINTS[rule], description, att.filename))

        if RTLO in att.filename:
            flag("rtlo", "Filename uses a hidden right-to-left character to disguise its real extension")
        if last in EXECUTABLE_EXTS:
            flag("executable", f"Attachment is an executable or script (.{last})")
        if len(exts) >= 2 and exts[-2] in DECOY_EXTS and last in EXECUTABLE_EXTS | HTML_EXTS | MACRO_EXTS:
            flag("double_extension", f"Double extension (.{exts[-2]}.{last}) disguises the real file type")
        if last in MACRO_EXTS:
            flag("macro_office", f"Macro-enabled Office document (.{last})")
        if last in ARCHIVE_EXTS:
            flag("archive", f"Archive or disk image (.{last}) can hide malicious files from scanners")
        if last in HTML_EXTS:
            flag("html_attachment", f"HTML/SVG attachment (.{last}) is often a local phishing page")
        if att.content_type in EXECUTABLE_MIME and last not in EXECUTABLE_EXTS:
            flag("executable_mime", f"Declared content type is executable ({att.content_type})")
        findings.append(finding)
    return findings, indicators
