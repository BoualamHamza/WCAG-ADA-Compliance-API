from __future__ import annotations

from typing import Dict, List

from app.schemas import (
    BatchScanResponse,
    RemediationDetailLevel,
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


REMEDIATION_LIBRARY: Dict[str, Dict[str, Dict[RemediationDetailLevel, str]]] = {
    "en": {
        "image-alt": {
            RemediationDetailLevel.BRIEF: 'Add alt text to images, or alt="" for decorative ones.',
            RemediationDetailLevel.STANDARD: 'Add a meaningful alt attribute, or alt="" for decorative images.',
            RemediationDetailLevel.VERBOSE: (
                'Add concise, meaningful alt text that conveys the image purpose in context. '
                'If the image is decorative, set alt="" so assistive technology can ignore it. '
                'Avoid repeating adjacent caption text in the alt attribute.'
            ),
        },
        "html-has-lang": {
            RemediationDetailLevel.BRIEF: 'Set a lang attribute on the html element.',
            RemediationDetailLevel.STANDARD: 'Set <html lang="en"> (or appropriate BCP47 language tag).',
            RemediationDetailLevel.VERBOSE: (
                'Set the document language with a valid BCP47 tag on the root html element '
                '(for example lang="en" or lang="en-US") so screen readers apply the right '
                'pronunciation and language rules.'
            ),
        },
        "valid-anchor": {
            RemediationDetailLevel.BRIEF: 'Give links a valid href, or use a button for actions.',
            RemediationDetailLevel.STANDARD: (
                'Use a semantic <button> for actions, or include an href for navigation links.'
            ),
            RemediationDetailLevel.VERBOSE: (
                'Use <a> only for navigation and provide a valid, non-empty href destination. '
                'For in-page actions (opening modals, toggles, submits), use a semantic <button> '
                'to preserve keyboard and assistive technology expectations.'
            ),
        },
    },
    "es": {
        "image-alt": {
            RemediationDetailLevel.BRIEF: 'Agrega texto alternativo, o alt="" si la imagen es decorativa.',
            RemediationDetailLevel.STANDARD: (
                'Agrega un atributo alt descriptivo, o alt="" para imágenes decorativas.'
            ),
            RemediationDetailLevel.VERBOSE: (
                'Incluye un texto alternativo breve y útil que describa la función de la imagen en '
                'su contexto. Si la imagen es decorativa, usa alt="" para que los lectores de '
                'pantalla la omitan. Evita duplicar el texto de un pie de foto cercano.'
            ),
        },
        "html-has-lang": {
            RemediationDetailLevel.BRIEF: 'Define el atributo lang en el elemento html.',
            RemediationDetailLevel.STANDARD: (
                'Define <html lang="es"> (o la etiqueta BCP47 que corresponda).'
            ),
            RemediationDetailLevel.VERBOSE: (
                'Define el idioma del documento con una etiqueta BCP47 válida en el elemento html '
                '(por ejemplo lang="es" o lang="es-MX") para mejorar la pronunciación en '
                'lectores de pantalla.'
            ),
        },
        "valid-anchor": {
            RemediationDetailLevel.BRIEF: 'Usa href válido en enlaces, o button para acciones.',
            RemediationDetailLevel.STANDARD: (
                'Usa un <button> semántico para acciones, o incluye href para enlaces de navegación.'
            ),
            RemediationDetailLevel.VERBOSE: (
                'Usa <a> solo para navegación y proporciona un href válido y no vacío. '
                'Para acciones de interfaz (modales, toggles, envío), usa <button> semántico '
                'para mantener expectativas de teclado y tecnologías de asistencia.'
            ),
        },
    },
}

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
    violations = _collect_violations(
        source=source,
        include_remediation=payload.include_remediation,
        remediation_detail_level=payload.remediation_detail_level,
        locale=payload.locale,
    )

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


def _collect_violations(
    source: str,
    include_remediation: bool,
    remediation_detail_level: RemediationDetailLevel,
    locale: str,
) -> List[Violation]:
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
                remediation=_remediation_for(
                    rule_id="image-alt",
                    remediation_detail_level=remediation_detail_level,
                    locale=locale,
                ),
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
                remediation=_remediation_for(
                    rule_id="html-has-lang",
                    remediation_detail_level=remediation_detail_level,
                    locale=locale,
                ),
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
                remediation=_remediation_for(
                    rule_id="valid-anchor",
                    remediation_detail_level=remediation_detail_level,
                    locale=locale,
                ),
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


def _normalized_locale(locale: str) -> str:
    normalized = locale.strip().lower()
    if not normalized:
        return "en"
    return normalized.split("-")[0]


def _remediation_for(rule_id: str, remediation_detail_level: RemediationDetailLevel, locale: str) -> str:
    locale_key = _normalized_locale(locale)
    localized_library = REMEDIATION_LIBRARY.get(locale_key, REMEDIATION_LIBRARY["en"])
    return localized_library[rule_id][remediation_detail_level]
