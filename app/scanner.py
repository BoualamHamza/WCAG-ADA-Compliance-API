from __future__ import annotations

import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from typing import Deque, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser
from uuid import uuid4

import httpx

from app.schemas import (
    BatchScanResponse,
    CheckFinding,
    CrawlDiffResponse,
    CrawlJobRequest,
    CrawlJobResponse,
    CrawlJobSummary,
    CrawlPageDiff,
    CrawlPageResult,
    JobStatus,
    RemediationDetailLevel,
    RetryWebhookResponse,
    RuleReference,
    RuleSetCreateRequest,
    RuleSetResponse,
    RuleSetsResponse,
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
CRAWL_JOBS: Dict[str, CrawlJobResponse] = {}
RULE_SETS: Dict[str, RuleSetResponse] = {}
REQUEST_TIMEOUT_SECONDS = 10.0
DEFAULT_USER_AGENT = "AccessCheckBot/0.8.1"

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
    RuleReference(
        rule_id="video-captions",
        description="Video caption quality requires manual verification.",
        wcag_sc="1.2.2",
        impact="serious",
    ),
    RuleReference(
        rule_id="keyboard-operability",
        description="Interactive keyboard behavior requires manual verification.",
        wcag_sc="2.1.1",
        impact="moderate",
    ),
]
RULE_REFERENCE_MAP: Dict[str, RuleReference] = {rule.rule_id: rule for rule in SUPPORTED_RULES}
SUPPORTED_RULE_IDS: Set[str] = set(RULE_REFERENCE_MAP)


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[tuple[str, Optional[str]]]) -> None:
        if tag != "a":
            return
        href = dict(attrs).get("href")
        if href:
            self.links.append(href)


def run_scan(payload: ScanRequest) -> ScanResponse:
    mode = ScanMode.URL if payload.url else ScanMode.HTML
    target = str(payload.url) if payload.url else "inline_html"
    source = _resolve_scan_source(payload)
    effective_rules = _resolve_effective_rules(
        run_only=payload.run_only,
        disable_rules=payload.disable_rules,
        rule_set_id=payload.rule_set_id,
    )

    violations = _collect_violations(
        source=source,
        include_remediation=payload.include_remediation,
        remediation_detail_level=payload.remediation_detail_level,
        locale=payload.locale,
        effective_rules=effective_rules,
    )
    passes = _collect_passes(source=source, effective_rules=effective_rules)
    incomplete = _collect_incomplete(source=source, effective_rules=effective_rules)

    score = compliance_score(v.impact for v in violations)
    pour = pour_breakdown(score)
    return ScanResponse(
        scan_mode=mode,
        target=target,
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


def create_crawl_job(payload: CrawlJobRequest) -> CrawlJobResponse:
    now = datetime.now(timezone.utc)
    effective_rules = sorted(
        _resolve_effective_rules(
            run_only=payload.run_only,
            disable_rules=payload.disable_rules,
            rule_set_id=payload.rule_set_id,
        )
    )
    job = CrawlJobResponse(
        rule_set_id=payload.rule_set_id,
        effective_rules=effective_rules,
        job_id=str(uuid4()),
        status=JobStatus.QUEUED,
        root_url=str(payload.url),
        max_pages=payload.max_pages,
        include_subdomains=payload.include_subdomains,
        max_concurrency=payload.max_concurrency,
        max_depth=payload.max_depth,
        respect_robots_txt=payload.respect_robots_txt,
        request_delay_ms=payload.request_delay_ms,
        user_agent=payload.user_agent,
        allowed_path_prefixes=payload.allowed_path_prefixes,
        excluded_path_prefixes=payload.excluded_path_prefixes,
        created_at=_iso_utc(now),
        updated_at=_iso_utc(now),
        summary=CrawlJobSummary(
            pages_scanned=0,
            pages_remaining=payload.max_pages,
            route_inventory=[],
            max_depth_reached=0,
        ),
        results=[],
    )
    CRAWL_JOBS[job.job_id] = job
    return job


def process_crawl_job(job_id: str) -> CrawlJobResponse:
    job = get_crawl_job(job_id)
    if job.status in {JobStatus.CANCELLED, JobStatus.COMPLETE, JobStatus.FAILED}:
        return job

    started = datetime.now(timezone.utc)
    job.status = JobStatus.RUNNING
    job.updated_at = _iso_utc(started)

    try:
        route_inventory = discover_routes(
            job.root_url,
            job.max_pages,
            include_subdomains=job.include_subdomains,
            max_depth=job.max_depth,
            respect_robots_txt=job.respect_robots_txt,
            request_delay_ms=job.request_delay_ms,
            user_agent=job.user_agent,
            allowed_path_prefixes=job.allowed_path_prefixes,
            excluded_path_prefixes=job.excluded_path_prefixes,
        )
        scan_routes = route_inventory
        if job.max_concurrency > 1 and job.request_delay_ms == 0:
            with ThreadPoolExecutor(max_workers=job.max_concurrency) as executor:
                results = list(
                    executor.map(lambda route: _scan_crawl_route(route, job.user_agent, job.effective_rules), scan_routes)
                )
        else:
            results = []
            for route in scan_routes:
                results.append(_scan_crawl_route(route, job.user_agent, job.effective_rules))
                if job.request_delay_ms > 0:
                    time.sleep(job.request_delay_ms / 1000)
        max_depth_reached = 0
        for result in results:
            max_depth_reached = max(max_depth_reached, result.depth)
    except Exception as error:  # noqa: BLE001
        failed = datetime.now(timezone.utc)
        job.status = JobStatus.FAILED
        job.updated_at = _iso_utc(failed)
        job.completed_at = _iso_utc(failed)
        job.error = str(error)
        CRAWL_JOBS[job_id] = job
        return job

    finished = datetime.now(timezone.utc)
    job.status = JobStatus.COMPLETE
    job.updated_at = _iso_utc(finished)
    job.completed_at = _iso_utc(finished)
    job.summary = CrawlJobSummary(
        pages_scanned=len(results),
        pages_remaining=max(job.max_pages - len(results), 0),
        route_inventory=[route["url"] for route in route_inventory],
        max_depth_reached=max_depth_reached,
    )
    job.results = results
    CRAWL_JOBS[job_id] = job
    return job


def get_crawl_job(job_id: str) -> CrawlJobResponse:
    job = CRAWL_JOBS.get(job_id)
    if job is None:
        raise KeyError(job_id)
    return job


def cancel_crawl_job(job_id: str) -> CrawlJobResponse:
    job = get_crawl_job(job_id)
    if job.status == JobStatus.COMPLETE:
        return job

    now = datetime.now(timezone.utc)
    job.status = JobStatus.CANCELLED
    job.updated_at = _iso_utc(now)
    job.completed_at = _iso_utc(now)
    job.summary.pages_remaining = max(job.max_pages - job.summary.pages_scanned, 0)
    CRAWL_JOBS[job_id] = job
    return job


def run_crawl_diff(baseline_job_id: str, current_job_id: str) -> CrawlDiffResponse:
    baseline_job = get_crawl_job(baseline_job_id)
    current_job = get_crawl_job(current_job_id)

    if baseline_job.status != JobStatus.COMPLETE or current_job.status != JobStatus.COMPLETE:
        raise ValueError("Both crawl jobs must be complete before diffing.")

    baseline_routes = set(baseline_job.summary.route_inventory)
    current_routes = set(current_job.summary.route_inventory)
    baseline_scores = [result.score for result in baseline_job.results]
    current_scores = [result.score for result in current_job.results]
    baseline_average = int(sum(baseline_scores) / len(baseline_scores)) if baseline_scores else 0
    current_average = int(sum(current_scores) / len(current_scores)) if current_scores else 0
    baseline_pages = {result.url: result for result in baseline_job.results}
    current_pages = {result.url: result for result in current_job.results}
    shared_pages = sorted(baseline_routes & current_routes)
    page_score_changes = []
    for url in shared_pages:
        baseline_page = baseline_pages[url]
        current_page = current_pages[url]
        baseline_violation_ids = {item.rule_id for item in baseline_page.scan.violations}
        current_violation_ids = {item.rule_id for item in current_page.scan.violations}
        page_score_changes.append(
            CrawlPageDiff(
                url=url,
                baseline_score=baseline_page.score,
                current_score=current_page.score,
                score_delta=current_page.score - baseline_page.score,
                baseline_violations=baseline_page.violations,
                current_violations=current_page.violations,
                new_violations=sorted(current_violation_ids - baseline_violation_ids),
                resolved_violations=sorted(baseline_violation_ids - current_violation_ids),
            )
        )

    return CrawlDiffResponse(
        baseline_job_id=baseline_job_id,
        current_job_id=current_job_id,
        baseline_pages=len(baseline_routes),
        current_pages=len(current_routes),
        pages_added=sorted(current_routes - baseline_routes),
        pages_removed=sorted(baseline_routes - current_routes),
        pages_unchanged=shared_pages,
        average_score_delta=current_average - baseline_average,
        page_score_changes=page_score_changes,
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


def get_rule_reference(rule_id: str) -> RuleReference:
    rule = RULE_REFERENCE_MAP.get(rule_id)
    if rule is None:
        raise KeyError(rule_id)
    return rule


def create_rule_set(payload: RuleSetCreateRequest) -> RuleSetResponse:
    include_rules = _validate_rule_ids(payload.include_rules)
    disable_rules = _validate_rule_ids(payload.disable_rules)
    effective_rules = _ensure_effective_rules(include_rules - disable_rules)

    now = datetime.now(timezone.utc)
    rule_set = RuleSetResponse(
        rule_set_id=str(uuid4()),
        name=payload.name,
        description=payload.description,
        include_rules=sorted(include_rules),
        disable_rules=sorted(disable_rules),
        effective_rules=sorted(effective_rules),
        created_at=_iso_utc(now),
        rule_count=len(effective_rules),
    )
    RULE_SETS[rule_set.rule_set_id] = rule_set
    return rule_set


def get_rule_set(rule_set_id: str) -> RuleSetResponse:
    rule_set = RULE_SETS.get(rule_set_id)
    if rule_set is None:
        raise KeyError(rule_set_id)
    return rule_set


def get_rule_sets() -> RuleSetsResponse:
    rule_sets = sorted(RULE_SETS.values(), key=lambda item: item.created_at)
    return RuleSetsResponse(count=len(rule_sets), rule_sets=rule_sets)


def discover_routes(
    root_url: str,
    max_pages: int,
    include_subdomains: bool = False,
    max_depth: int = 1,
    respect_robots_txt: bool = True,
    request_delay_ms: int = 0,
    user_agent: str = DEFAULT_USER_AGENT,
    allowed_path_prefixes: Optional[List[str]] = None,
    excluded_path_prefixes: Optional[List[str]] = None,
) -> List[dict]:
    normalized_root_url = root_url.rstrip("/") or root_url
    allowed_path_prefixes = allowed_path_prefixes or []
    excluded_path_prefixes = excluded_path_prefixes or []
    routes: List[dict] = [{"url": normalized_root_url, "depth": 0, "parent_url": None}]
    seen = {normalized_root_url}
    queue: Deque[dict] = deque(routes)
    robot_parser = _load_robots_parser(normalized_root_url, user_agent) if respect_robots_txt else None

    while queue and len(routes) < max_pages:
        current = queue.popleft()
        if current["depth"] >= max_depth:
            continue
        html = _fetch_url_content(current["url"], user_agent=user_agent)
        discovered = _extract_same_site_links(
            current["url"],
            html,
            include_subdomains=include_subdomains,
            robot_parser=robot_parser,
            user_agent=user_agent,
            allowed_path_prefixes=allowed_path_prefixes,
            excluded_path_prefixes=excluded_path_prefixes,
        )
        for link in discovered:
            if link in seen:
                continue
            page = {"url": link, "depth": current["depth"] + 1, "parent_url": current["url"]}
            seen.add(link)
            routes.append(page)
            queue.append(page)
            if len(routes) >= max_pages:
                break
        if request_delay_ms > 0:
            time.sleep(request_delay_ms / 1000)
    return routes[:max_pages]


def _resolve_scan_source(payload: ScanRequest) -> str:
    if payload.html:
        return payload.html
    if payload.url:
        try:
            return _fetch_url_content(str(payload.url))
        except httpx.HTTPError:
            return str(payload.url)
    return ""


def _fetch_url_content(url: str, user_agent: str = DEFAULT_USER_AGENT) -> str:
    with httpx.Client(
        follow_redirects=True,
        timeout=REQUEST_TIMEOUT_SECONDS,
        headers={"User-Agent": user_agent},
    ) as client:
        response = client.get(url)
        response.raise_for_status()
        return response.text


def _extract_same_site_links(
    root_url: str,
    html: str,
    include_subdomains: bool = False,
    robot_parser: Optional[RobotFileParser] = None,
    user_agent: str = DEFAULT_USER_AGENT,
    allowed_path_prefixes: Optional[List[str]] = None,
    excluded_path_prefixes: Optional[List[str]] = None,
) -> List[str]:
    allowed_path_prefixes = allowed_path_prefixes or []
    excluded_path_prefixes = excluded_path_prefixes or []
    parser = _LinkExtractor()
    parser.feed(html)
    root = urlparse(root_url)
    links: List[str] = []
    for href in parser.links:
        absolute = urljoin(root_url, href)
        parsed = urlparse(absolute)
        if parsed.scheme not in {"http", "https"}:
            continue
        if not _is_same_site(root.hostname or "", parsed.hostname or "", include_subdomains):
            continue
        if robot_parser and not robot_parser.can_fetch(user_agent, absolute):
            continue
        if excluded_path_prefixes and any(parsed.path.startswith(prefix) for prefix in excluded_path_prefixes):
            continue
        if allowed_path_prefixes and not any(parsed.path.startswith(prefix) for prefix in allowed_path_prefixes):
            continue
        normalized = absolute.rstrip("/") or absolute
        if normalized not in links:
            links.append(normalized)
    return links


def _is_same_site(root_host: str, candidate_host: str, include_subdomains: bool) -> bool:
    if candidate_host == root_host:
        return True
    if include_subdomains and candidate_host.endswith(f".{root_host}"):
        return True
    return False


def _load_robots_parser(root_url: str, user_agent: str) -> RobotFileParser:
    parser = RobotFileParser()
    robots_url = urljoin(root_url, "/robots.txt")
    try:
        parser.parse(_fetch_url_content(robots_url, user_agent=user_agent).splitlines())
    except httpx.HTTPError:
        parser.parse([])
    return parser


def _scan_crawl_route(route: dict, user_agent: str, effective_rules: Optional[List[str]] = None) -> CrawlPageResult:
    source = _fetch_url_content(route["url"], user_agent=user_agent)
    scan = run_scan(ScanRequest(html=source, run_only=effective_rules))
    scan.scan_mode = ScanMode.URL
    scan.target = route["url"]
    scan.static_scan_warning = False
    return CrawlPageResult(
        url=route["url"],
        depth=route["depth"],
        parent_url=route["parent_url"],
        score=scan.score,
        violations=scan.totals["violations"],
        scan=scan,
    )


def _collect_violations(
    source: str,
    include_remediation: bool,
    remediation_detail_level: RemediationDetailLevel,
    locale: str,
    effective_rules: Set[str],
) -> List[Violation]:
    findings: List[Violation] = []
    lower = source.lower()

    if "image-alt" in effective_rules and "<img" in lower and "alt=" not in lower:
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

    if "html-has-lang" in effective_rules and "<html" in lower and "lang=" not in lower:
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

    if "valid-anchor" in effective_rules and "<a" in lower and "href" not in lower:
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


def _collect_passes(source: str, effective_rules: Set[str]) -> List[CheckFinding]:
    passes: List[CheckFinding] = []
    lower = source.lower()

    if "image-alt" in effective_rules and "<img" in lower and "alt=" in lower:
        passes.append(
            CheckFinding(
                rule_id="image-alt",
                message="Image elements include alternate text.",
                wcag_sc="1.1.1",
                impact="serious",
                confidence=0.94,
            )
        )

    if "html-has-lang" in effective_rules and "<html" in lower and "lang=" in lower:
        passes.append(
            CheckFinding(
                rule_id="html-has-lang",
                message="The html element declares a language attribute.",
                wcag_sc="3.1.1",
                impact="moderate",
                confidence=0.97,
            )
        )

    if "valid-anchor" in effective_rules and "<a" in lower and "href" in lower:
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


def _collect_incomplete(source: str, effective_rules: Set[str]) -> List[CheckFinding]:
    lower = source.lower()
    incomplete: List[CheckFinding] = []

    if "video-captions" in effective_rules and "<video" in lower:
        incomplete.append(
            CheckFinding(
                rule_id="video-captions",
                message="Video caption quality requires manual verification.",
                wcag_sc="1.2.2",
                impact="serious",
                confidence=0.52,
            )
        )

    if "keyboard-operability" in effective_rules and "onclick=" in lower:
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


def _validate_rule_ids(rule_ids: Optional[List[str]]) -> Set[str]:
    selected = set(rule_ids or [])
    unknown = sorted(selected - SUPPORTED_RULE_IDS)
    if unknown:
        raise ValueError(f"Unsupported rule ids: {', '.join(unknown)}")
    return selected


def _ensure_effective_rules(rule_ids: Set[str]) -> Set[str]:
    if not rule_ids:
        raise ValueError("At least one effective rule must remain after applying filters.")
    return rule_ids


def _resolve_effective_rules(
    run_only: Optional[List[str]] = None,
    disable_rules: Optional[List[str]] = None,
    rule_set_id: Optional[str] = None,
) -> Set[str]:
    disabled = _validate_rule_ids(disable_rules)
    selected = SUPPORTED_RULE_IDS.copy()
    if rule_set_id:
        selected = set(get_rule_set(rule_set_id).effective_rules)
    if run_only is not None:
        selected = _validate_rule_ids(run_only)
    return _ensure_effective_rules(selected - disabled)


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
