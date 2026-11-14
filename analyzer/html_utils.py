"""Minimal, safe HTML scanning with the standard library.

We never render email HTML. We only *read* it to get:
* the visible text (for keyword detection), and
* links with their visible anchor text (for URL checks).

Scripts and styles are skipped. No network requests are made, so remote
images or tracking pixels are never loaded.
"""

from __future__ import annotations

from html.parser import HTMLParser

_SKIP_TAGS = {"script", "style", "head", "title", "noscript"}


class _Scanner(HTMLParser):
    """Collects visible text and (href, anchor_text) pairs."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text_parts: list[str] = []
        self.links: list[tuple[str, str]] = []
        self._skip_depth = 0
        self._href: str | None = None
        self._anchor_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): (value or "") for name, value in attrs}
        if tag in _SKIP_TAGS:
            self._skip_depth += 1
        elif tag == "a":
            self._href = attributes.get("href", "").strip()
            self._anchor_parts = []
        elif tag == "form" and attributes.get("action"):
            # A form inside an email is a classic credential-harvesting trick.
            self.links.append((attributes["action"].strip(), ""))
        # Block-ish tags separate words in the text output.
        self.text_parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TAGS and self._skip_depth:
            self._skip_depth -= 1
        elif tag == "a" and self._href is not None:
            anchor = " ".join("".join(self._anchor_parts).split())
            self.links.append((self._href, anchor))
            self._href = None
        self.text_parts.append(" ")

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self.text_parts.append(data)
        if self._href is not None:
            self._anchor_parts.append(data)


def _scan(html: str) -> _Scanner:
    scanner = _Scanner()
    try:
        scanner.feed(html or "")
        scanner.close()
    except Exception:  # noqa: BLE001 - malformed HTML must never crash analysis
        pass
    return scanner


def html_to_text(html: str) -> str:
    """Return the visible text of an HTML document, whitespace collapsed."""
    return " ".join("".join(_scan(html).text_parts).split())


def extract_links(html: str) -> list[tuple[str, str]]:
    """Return (href, anchor_text) for every <a href> and <form action>."""
    return _scan(html).links
