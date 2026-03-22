from __future__ import annotations

import re
from typing import Any, Iterable, List, Tuple

from app.schemas import CheckFinding, Violation

_WCAG_RE = re.compile(r"^wcag(\d)(\d)(\d)$")


def _extract_wcag_sc(tags: Iterable[str]) -> str:
    for tag in tags:
        match = _WCAG_RE.match(tag)
        if match:
            return ".".join(match.groups())
    return "manual-review"


def _selector(item: dict[str, Any]) -> str:
    nodes = item.get("nodes") or []
    if not nodes:
        return "document"
    targets = nodes[0].get("target") or []
    return targets[0] if targets else "document"


def _remediation(item: dict[str, Any]) -> str | None:
    nodes = item.get("nodes") or []
    if not nodes:
        return None
    return nodes[0].get("failureSummary") or item.get("help")


def map_violations(items: List[dict[str, Any]], include_remediation: bool) -> List[Violation]:
    violations: List[Violation] = []
    for item in items:
        violations.append(
            Violation(
                rule_id=item["id"],
                message=item.get("description") or item.get("help") or item["id"],
                impact=item.get("impact") or "minor",
                wcag_sc=_extract_wcag_sc(item.get("tags", [])),
                selector=_selector(item),
                remediation=_remediation(item) if include_remediation else None,
            )
        )
    return violations


def _finding(item: dict[str, Any], confidence: float) -> CheckFinding:
    return CheckFinding(
        rule_id=item["id"],
        message=item.get("description") or item.get("help") or item["id"],
        wcag_sc=_extract_wcag_sc(item.get("tags", [])),
        impact=item.get("impact") or "minor",
        confidence=confidence,
    )


def map_axe_results(result: dict[str, Any], include_remediation: bool) -> Tuple[List[Violation], List[CheckFinding], List[CheckFinding]]:
    return (
        map_violations(result.get("violations", []), include_remediation),
        [_finding(item, 0.95) for item in result.get("passes", [])],
        [_finding(item, 0.5) for item in result.get("incomplete", [])],
    )
