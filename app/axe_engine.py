from __future__ import annotations

import base64
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from playwright.sync_api import Browser, BrowserContext, Page, Playwright, TimeoutError as PlaywrightTimeoutError, sync_playwright

STANDARD_TAG_MAP = {
    "wcag20a": "wcag2a",
    "wcag20aa": "wcag2aa",
    "wcag21a": "wcag21a",
    "wcag21aa": "wcag21aa",
    "wcag22a": "wcag22a",
    "wcag22aa": "wcag22aa",
    "wcag22aaa": "wcag22aaa",
    "section508": "section508",
    "eaa": "TTv5",
    "best-practice": "best-practice",
    "wcag2.1aa": "wcag21aa",
    "wcag2.2aa": "wcag22aa",
}
AXE_CDN_URL = "https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.10.3/axe.min.js"

EXPANDED_STANDARD_TAGS = {
    "wcag20a": ["wcag2a"],
    "wcag20aa": ["wcag2a", "wcag2aa"],
    "wcag21a": ["wcag2a", "wcag21a"],
    "wcag21aa": ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"],
    "wcag22a": ["wcag2a", "wcag21a", "wcag22a"],
    "wcag22aa": ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22a", "wcag22aa"],
    "wcag22aaa": ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22a", "wcag22aa", "wcag22aaa"],
    "section508": ["section508"],
    "eaa": ["TTv5"],
    "best-practice": ["best-practice"],
    "wcag2.1aa": ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"],
    "wcag2.2aa": ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22a", "wcag22aa"],
}
DEFAULT_TIMEOUT_MS = 30_000
HTML_TIMEOUT_MS = 10_000


class AxeEngineError(RuntimeError):
    pass


class RenderTimeoutError(AxeEngineError):
    pass


@dataclass(slots=True)
class AxeScanOptions:
    run_only: Optional[List[str]]
    disable_rules: List[str]
    standards: List[str]
    viewport: Dict[str, int]
    include_hidden: bool = False
    wait_until: str = "networkidle"


_RULE_CACHE: List[dict[str, Any]] | None = None


@lru_cache(maxsize=1)
def _axe_script() -> str:
    local_asset = Path(__file__).with_name("axe.min.js")
    if local_asset.exists():
        return local_asset.read_text(encoding="utf-8")
    response = httpx.get(AXE_CDN_URL, timeout=30.0)
    response.raise_for_status()
    return response.text


def build_axe_options(*, run_only: Optional[List[str]], disable_rules: Optional[List[str]], standards: Optional[List[str]]) -> dict[str, Any]:
    tags: list[str] = []
    for item in standards or []:
        tags.extend(EXPANDED_STANDARD_TAGS.get(item, [STANDARD_TAG_MAP.get(item, item)]))
    tags = list(dict.fromkeys(tags))
    options: dict[str, Any] = {"reporter": "v2", "resultTypes": ["violations", "passes", "incomplete", "inapplicable"]}
    if run_only:
        options["runOnly"] = {"type": "rule", "values": run_only}
    elif tags:
        options["runOnly"] = {"type": "tag", "values": tags}
    if disable_rules:
        options["rules"] = {rule_id: {"enabled": False} for rule_id in disable_rules}
    return options


def _inject_axe(page: Page) -> None:
    page.add_script_tag(content=_axe_script())


def _run_axe(page: Page, options: dict[str, Any]) -> dict[str, Any]:
    return page.evaluate(
        """async ({ options }) => {
            const results = await axe.run(document, options);
            return JSON.parse(JSON.stringify(results));
        }""",
        {"options": options},
    )


def scan_html(html: str, options: AxeScanOptions) -> dict[str, Any]:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(viewport=options.viewport)
        page = context.new_page()
        try:
            encoded = base64.b64encode(html.encode("utf-8")).decode("ascii")
            page.goto(f"data:text/html;base64,{encoded}", wait_until="load", timeout=HTML_TIMEOUT_MS)
            _inject_axe(page)
            return _run_axe(page, build_axe_options(run_only=options.run_only, disable_rules=options.disable_rules, standards=options.standards))
        except PlaywrightTimeoutError as exc:
            raise RenderTimeoutError("Timed out while rendering HTML input.") from exc
        finally:
            context.close()
            browser.close()


def scan_url(url: str, options: AxeScanOptions) -> dict[str, Any]:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(viewport=options.viewport)
        page = context.new_page()
        try:
            page.goto(url, wait_until=options.wait_until, timeout=DEFAULT_TIMEOUT_MS)
            _inject_axe(page)
            return _run_axe(page, build_axe_options(run_only=options.run_only, disable_rules=options.disable_rules, standards=options.standards))
        except PlaywrightTimeoutError as exc:
            raise RenderTimeoutError(f"Timed out while rendering {url}.") from exc
        finally:
            context.close()
            browser.close()


def get_rules() -> List[dict[str, Any]]:
    global _RULE_CACHE
    if _RULE_CACHE is not None:
        return _RULE_CACHE
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1280, "height": 720})
        page = context.new_page()
        try:
            page.goto("data:text/html,<html><head><title>rules</title></head><body></body></html>", wait_until="load")
            _inject_axe(page)
            _RULE_CACHE = page.evaluate("() => JSON.parse(JSON.stringify(axe.getRules()))")
            return _RULE_CACHE
        finally:
            context.close()
            browser.close()
