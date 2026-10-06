"""Static checks of the interface: CSP compliance, XSS policy and wiring.

They do not replace the browser walkthroughs documented in the README, but they
catch the regressions that break a view silently (a renamed element id, an
inline handler blocked by the CSP, an unregistered view).
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

from app.config import FRONTEND_DIR

JS_FILES = sorted((FRONTEND_DIR / "js").glob("*.js"))
INDEX = (FRONTEND_DIR / "index.html").read_text(encoding="utf-8")


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.scripts: list[dict] = []
        self.links: list[dict] = []
        self.inline_handlers: list[str] = []
        self.inline_script = False
        self.nav_views: list[str] = []
        self.sections: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if "id" in attributes:
            self.ids.append(attributes["id"])
        self.inline_handlers += [name for name, _ in attrs if name.startswith("on")]
        if tag == "script":
            self.scripts.append(attributes)
            self._in_script = True
        if tag == "link":
            self.links.append(attributes)
        if "nav-item" in (attributes.get("class") or "") and attributes.get("data-view"):
            self.nav_views.append(attributes["data-view"])
        if tag == "section" and (attributes.get("id") or "").startswith("view-"):
            self.sections.append(attributes["id"][5:])

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script and data.strip():
            self.inline_script = True


def _page() -> _Collector:
    collector = _Collector()
    collector.feed(INDEX)
    return collector


def _js() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in JS_FILES)


def test_no_inline_script_or_handler():
    """The CSP (script-src 'self') would block them: the button would silently do nothing."""
    page = _page()
    assert not page.inline_script
    assert page.inline_handlers == []
    assert all(script.get("src") for script in page.scripts)


def test_local_assets_exist():
    page = _page()
    for script in page.scripts:
        assert (FRONTEND_DIR / script["src"]).is_file(), script["src"]
    for link in page.links:
        href = link.get("href", "")
        assert not href.startswith(("http:", "https:", "//")), f"external resource: {href}"
        assert (FRONTEND_DIR / href).is_file(), href


def test_unique_ids():
    ids = _page().ids
    assert len(ids) == len(set(ids)), sorted({i for i in ids if ids.count(i) > 1})


def test_every_referenced_element_exists():
    """Each $("#id") used by the scripts exists in the page or is created by a script."""
    js = _js()
    referenced = set(re.findall(r'\$\("#([A-Za-z0-9_-]+)', js)) | set(
        re.findall(r'getElementById\("([A-Za-z0-9_-]+)"', js)
    )
    created = set(re.findall(r'\bid: "([A-Za-z0-9_-]+)"', js))
    missing = referenced - set(_page().ids) - created
    assert not missing, sorted(missing)


def test_no_html_injection_sinks():
    """Server data (app names, file names, logs) reaches the DOM through textContent only."""
    code = re.sub(r"/\*.*?\*/|//[^\n]*", "", _js(), flags=re.S)
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert sink not in code, sink


def test_navigation_matches_registered_views():
    page = _page()
    registered = set(re.findall(r'registerView\("([a-z]+)"', _js()))
    assert set(page.nav_views) == registered == set(page.sections)


def test_buttons_have_explicit_type():
    """A button without type inside a form would submit it; we never rely on that default."""
    for match in re.finditer(r"<button\b[^>]*>", INDEX):
        assert 'type="' in match.group(0), match.group(0)


def test_api_calls_target_existing_routes(client):
    """Every /api/... path written in the scripts exists on the server."""
    paths = {re.sub(r"\{[^}]+\}$", "", path) for path in client.app.openapi()["paths"]}
    used = set(re.findall(r'"(/api/[a-z/_-]+)', _js()))
    unknown = {path for path in used if path.rstrip("/") not in paths and not any(p.startswith(path) for p in paths)}
    assert not unknown, sorted(unknown)
