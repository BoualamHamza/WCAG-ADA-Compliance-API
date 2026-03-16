from __future__ import annotations

from typing import List

from app.schemas import (
    BatchScanResponse,
    RuleReference,
    RulesResponse,
    ScanMode,
    ScanRequest,
    ScanResponse,
    Violation,
)
from app.scoring import compliance_score, pour_breakdown

DISCLAIMER = (
    "This automated scan detects approximately 40–57% of potential WCAG accessibility issues. "
    "A passing score or low violation count does not constitute legal ADA or WCAG compliance. "
    "Automated testing cannot evaluate subjective criteria, dynamic interactions, or issues requiring "
    "human judgment. A complete compliance assessment requires manual expert review and user testing "
    "with people who have disabilities. This API is a development and auditing tool, not a legal "
    "certification service."
)

SUPPORTED_RULES: List[RuleReference] = [
    RuleReference(
        rule_id="image-alt",
        description="Image elements must have alternate text.",
        wcag_sc="1.1.1",
        impact="serious",
    ),
    RuleReference(
        rule_id="html-has-lang",
        description="The html element must have a lang attribute.",
        wcag_sc="3.1.1",
        impact="moderate",
    ),
    RuleReference(
        rule_id="valid-anchor",
        description="Anchor elements should have a valid href attribute.",
        wcag_sc="2.4.4",
        impact="minor",
    ),
]


def run_scan(payload: ScanRequest) -> ScanResponse:
    mode = ScanMode.URL if payload.url else ScanMode.HTML
    source = str(payload.url) if payload.url else (payload.html or "")
    violations = _collect_violations(source, payload.include_remediation)

    score = compliance_score(v.impact for v in violations)
    pour = pour_breakdown(score)
    return ScanResponse(
        scan_mode=mode,
        target=str(payload.url) if payload.url else "inline_html",
        violations=violations,
        totals={
            "violations": len(violations),
            "incomplete": 0,
            "passes": max(0, 40 - len(violations)),
            "inapplicable": 0,
        },
        score=score,
        pour_breakdown=pour,
        static_scan_warning=mode == ScanMode.HTML,
        coverage_disclaimer=DISCLAIMER,
    )


def run_batch_scan(scans: List[ScanRequest]) -> BatchScanResponse:
    results = [run_scan(scan) for scan in scans]
    average_score = int(sum(result.score for result in results) / len(results))
    return BatchScanResponse(total_scans=len(results), average_score=average_score, results=results)


def get_supported_rules() -> RulesResponse:
    return RulesResponse(count=len(SUPPORTED_RULES), rules=SUPPORTED_RULES)


def _collect_violations(source: str, include_remediation: bool) -> List[Violation]:
    findings: List[Violation] = []
    lower = source.lower()

    if "<img" in lower and "alt=" not in lower:
        findings.append(
            _violation(
                rule_id="image-alt",
                message="Image elements must have alternate text.",
                impact="serious",
                wcag_sc="1.1.1",
                selector="img",
                include_remediation=include_remediation,
                remediation='Add a meaningful alt attribute, or alt="" for decorative images.',
            )
        )

    if "<html" in lower and "lang=" not in lower:
        findings.append(
            _violation(
                rule_id="html-has-lang",
                message="The html element must have a lang attribute.",
                impact="moderate",
                wcag_sc="3.1.1",
                selector="html",
                include_remediation=include_remediation,
                remediation='Set <html lang="en"> (or appropriate BCP47 language tag).',
            )
        )

    if "<a" in lower and "href" not in lower:
        findings.append(
            _violation(
                rule_id="valid-anchor",
                message="Anchor elements should have a valid href attribute.",
                impact="minor",
                wcag_sc="2.4.4",
                selector="a",
                include_remediation=include_remediation,
                remediation="Use a semantic <button> for actions, or include an href for navigation links.",
            )
        )

    return findings


def _violation(
    rule_id: str,
    message: str,
    impact: str,
    wcag_sc: str,
    selector: str,
    include_remediation: bool,
    remediation: str,
) -> Violation:
    return Violation(
        rule_id=rule_id,
        message=message,
        impact=impact,
        wcag_sc=wcag_sc,
        selector=selector,
        remediation=remediation if include_remediation else None,
    )
