from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from uuid import uuid4

from app.schemas import (
    BatchScanResponse,
    CheckFinding,
    RemediationDetailLevel,
    RetryWebhookResponse,
    RuleReference,
    RulesResponse,
    ScanDiffResponse,
    ScanMode,
    ScanRequest,
    ScanResponse,
    Violation,
    WebhookDelivery,
    WebhookDeliveryAttempt,
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

WEBHOOK_DELIVERIES: Dict[str, WebhookDelivery] = {}

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
    passes = _collect_passes(source=source)
    incomplete = _collect_incomplete(source=source)

    score = compliance_score(v.impact for v in violations)
    pour = pour_breakdown(score)
    return ScanResponse(
        scan_mode=mode,
        target=str(payload.url) if payload.url else "inline_html",
        violations=violations,
        passes=passes,
        incomplete=incomplete,
        totals={
            "violations": len(violations),
            "incomplete": len(incomplete),
            "passes": len(passes),
            "inapplicable": 0,
        },
        score=score,
        pour_breakdown=pour,
        static_scan_warning=mode == ScanMode.HTML,
        coverage_disclaimer=DISCLAIMER,
    )


def run_batch_scan(scans: List[ScanRequest], webhook_url: Optional[str] = None) -> BatchScanResponse:
    results = [run_scan(scan) for scan in scans]
    average_score = int(sum(result.score for result in results) / len(results))
    callback = _register_webhook_delivery(url=webhook_url, total_scans=len(results)) if webhook_url else None
    return BatchScanResponse(
        total_scans=len(results),
        average_score=average_score,
        results=results,
        callback=callback,
    )


def retry_webhook_delivery(delivery_id: str) -> RetryWebhookResponse:
    callback = WEBHOOK_DELIVERIES.get(delivery_id)
    if callback is None:
        raise KeyError(delivery_id)

    callback.attempts += 1
    if callback.attempts >= callback.max_attempts:
        callback.status = "failed"
        callback.next_attempt_at = None
        detail = "Maximum retry attempts reached."
    else:
        callback.status = "retrying"
        callback.next_attempt_at = _iso_utc(datetime.now(timezone.utc) + timedelta(minutes=5))
        detail = "Retry scheduled for callback delivery."

    callback.history.append(
        WebhookDeliveryAttempt(
            attempt=callback.attempts,
            status=callback.status,
            timestamp=_iso_utc(datetime.now(timezone.utc)),
            detail=detail,
        )
    )
    WEBHOOK_DELIVERIES[delivery_id] = callback
    return RetryWebhookResponse(callback=callback)


def run_diff_scan(baseline: ScanRequest, current: ScanRequest) -> ScanDiffResponse:
    baseline_scan = run_scan(baseline)
    current_scan = run_scan(current)

    baseline_ids = {item.rule_id for item in baseline_scan.violations}
    current_ids = {item.rule_id for item in current_scan.violations}

    return ScanDiffResponse(
        baseline_score=baseline_scan.score,
        current_score=current_scan.score,
        score_delta=current_scan.score - baseline_scan.score,
        new_violations=sorted(list(current_ids - baseline_ids)),
        resolved_violations=sorted(list(baseline_ids - current_ids)),
    )


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


def _collect_passes(source: str) -> List[CheckFinding]:
    passes: List[CheckFinding] = []
    lower = source.lower()

    if "<img" in lower and "alt=" in lower:
        passes.append(
            CheckFinding(
                rule_id="image-alt",
                message="Image elements include alternate text.",
                wcag_sc="1.1.1",
                impact="serious",
                confidence=0.94,
            )
        )

    if "<html" in lower and "lang=" in lower:
        passes.append(
            CheckFinding(
                rule_id="html-has-lang",
                message="The html element declares a language attribute.",
                wcag_sc="3.1.1",
                impact="moderate",
                confidence=0.97,
            )
        )

    if "<a" in lower and "href" in lower:
        passes.append(
            CheckFinding(
                rule_id="valid-anchor",
                message="Anchor elements include href destinations.",
                wcag_sc="2.4.4",
                impact="minor",
                confidence=0.9,
            )
        )

    return passes


def _collect_incomplete(source: str) -> List[CheckFinding]:
    lower = source.lower()
    incomplete: List[CheckFinding] = []

    if "<video" in lower:
        incomplete.append(
            CheckFinding(
                rule_id="video-captions",
                message="Video caption quality requires manual verification.",
                wcag_sc="1.2.2",
                impact="serious",
                confidence=0.52,
            )
        )

    if "onclick=" in lower:
        incomplete.append(
            CheckFinding(
                rule_id="keyboard-operability",
                message="Interactive keyboard behavior requires manual verification.",
                wcag_sc="2.1.1",
                impact="moderate",
                confidence=0.48,
            )
        )

    return incomplete


def _register_webhook_delivery(url: Optional[str], total_scans: int) -> Optional[WebhookDelivery]:
    if url is None:
        return None
    now = datetime.now(timezone.utc)
    delivery_id = str(uuid4())
    delivery = WebhookDelivery(
        delivery_id=delivery_id,
        webhook_url=url,
        status="queued",
        event="scan.batch.completed",
        expected_notifications=1,
        registered_at=_iso_utc(now),
        total_scans=total_scans,
        attempts=0,
        max_attempts=3,
        next_attempt_at=_iso_utc(now + timedelta(minutes=5)),
        history=[],
    )
    WEBHOOK_DELIVERIES[delivery_id] = delivery
    return delivery


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


def _iso_utc(value: datetime) -> str:
    return value.isoformat()
