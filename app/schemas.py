from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl, model_validator


class ScanMode(str, Enum):
    URL = "url"
    HTML = "html"


class RemediationDetailLevel(str, Enum):
    BRIEF = "brief"
    STANDARD = "standard"
    VERBOSE = "verbose"


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"




class RuleSelectionMixin(BaseModel):
    run_only: Optional[List[str]] = None
    disable_rules: List[str] = Field(default_factory=list)
    rule_set_id: Optional[str] = None


class ScanRequest(RuleSelectionMixin):
    url: Optional[HttpUrl] = None
    html: Optional[str] = None
    include_remediation: bool = Field(default=False)
    remediation_detail_level: RemediationDetailLevel = Field(default=RemediationDetailLevel.STANDARD)
    locale: str = Field(default="en")
    standards: List[str] = Field(default_factory=lambda: ["wcag2.1aa", "wcag2.2aa"])

    @model_validator(mode="after")
    def validate_exactly_one_input(cls, model: "ScanRequest") -> "ScanRequest":
        has_url = model.url is not None
        has_html = bool(model.html)
        if has_url == has_html:
            raise ValueError("Provide exactly one input: either `url` or `html`.")
        return model


class Violation(BaseModel):
    rule_id: str
    message: str
    impact: str
    wcag_sc: str
    selector: str
    remediation: Optional[str] = None


class CheckFinding(BaseModel):
    rule_id: str
    message: str
    wcag_sc: str
    impact: str
    confidence: float = Field(ge=0.0, le=1.0)


class PourBreakdown(BaseModel):
    perceivable: int
    operable: int
    understandable: int
    robust: int


class ScanResponse(BaseModel):
    scan_mode: ScanMode
    target: str
    violations: List[Violation]
    passes: List[CheckFinding] = Field(default_factory=list)
    incomplete: List[CheckFinding] = Field(default_factory=list)
    totals: dict
    score: int
    pour_breakdown: PourBreakdown
    static_scan_warning: bool = False
    coverage_disclaimer: str


class BatchScanRequest(BaseModel):
    scans: List[ScanRequest] = Field(min_length=1, max_length=10)
    webhook_url: Optional[HttpUrl] = None


class WebhookDeliveryAttempt(BaseModel):
    attempt: int
    status: str
    timestamp: str
    detail: str


class WebhookDelivery(BaseModel):
    delivery_id: str
    webhook_url: str
    status: str
    event: str
    expected_notifications: int
    registered_at: str
    total_scans: int
    attempts: int
    max_attempts: int
    next_attempt_at: Optional[str] = None
    history: List[WebhookDeliveryAttempt] = Field(default_factory=list)


class BatchScanResponse(BaseModel):
    total_scans: int
    average_score: int
    results: List[ScanResponse]
    callback: Optional[WebhookDelivery] = None


class RuleReference(BaseModel):
    rule_id: str
    description: str
    wcag_sc: str
    impact: str


class RulesResponse(BaseModel):
    count: int
    rules: List[RuleReference]


class RuleSetCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=500)
    include_rules: List[str] = Field(min_length=1)
    disable_rules: List[str] = Field(default_factory=list)


class RuleSetResponse(BaseModel):
    rule_set_id: str
    name: str
    description: Optional[str] = None
    include_rules: List[str]
    disable_rules: List[str] = Field(default_factory=list)
    effective_rules: List[str] = Field(default_factory=list)
    created_at: str
    rule_count: int


class RuleSetsResponse(BaseModel):
    count: int
    rule_sets: List[RuleSetResponse]


class RetryWebhookResponse(BaseModel):
    callback: WebhookDelivery


class ScanDiffRequest(BaseModel):
    baseline: ScanRequest
    current: ScanRequest


class ScanDiffResponse(BaseModel):
    baseline_score: int
    current_score: int
    score_delta: int
    new_violations: List[str]
    resolved_violations: List[str]


class CrawlJobRequest(RuleSelectionMixin):
    url: HttpUrl
    max_pages: int = Field(default=25, ge=1, le=500)
    include_subdomains: bool = False
    max_concurrency: int = Field(default=1, ge=1, le=10)
    max_depth: int = Field(default=1, ge=0, le=5)
    respect_robots_txt: bool = True
    request_delay_ms: int = Field(default=0, ge=0, le=5000)
    user_agent: str = Field(default="AccessCheckBot/0.8.1")
    allowed_path_prefixes: List[str] = Field(default_factory=list)
    excluded_path_prefixes: List[str] = Field(default_factory=list)


class CrawlJobSummary(BaseModel):
    pages_scanned: int
    pages_remaining: int
    route_inventory: List[str] = Field(default_factory=list)
    max_depth_reached: int = 0


class CrawlPageResult(BaseModel):
    url: str
    depth: int
    parent_url: Optional[str] = None
    score: int
    violations: int
    scan: ScanResponse


class CrawlPageDiff(BaseModel):
    url: str
    baseline_score: int
    current_score: int
    score_delta: int
    baseline_violations: int
    current_violations: int
    new_violations: List[str] = Field(default_factory=list)
    resolved_violations: List[str] = Field(default_factory=list)


class CrawlJobResponse(BaseModel):
    rule_set_id: Optional[str] = None
    effective_rules: List[str] = Field(default_factory=list)
    job_id: str
    status: JobStatus
    root_url: str
    max_pages: int
    include_subdomains: bool
    max_concurrency: int
    max_depth: int
    respect_robots_txt: bool
    request_delay_ms: int
    user_agent: str
    allowed_path_prefixes: List[str] = Field(default_factory=list)
    excluded_path_prefixes: List[str] = Field(default_factory=list)
    created_at: str
    updated_at: str
    completed_at: Optional[str] = None
    summary: CrawlJobSummary
    results: List[CrawlPageResult] = Field(default_factory=list)
    error: Optional[str] = None


class CrawlDiffRequest(BaseModel):
    baseline_job_id: str
    current_job_id: str


class CrawlDiffResponse(BaseModel):
    baseline_job_id: str
    current_job_id: str
    baseline_pages: int
    current_pages: int
    pages_added: List[str]
    pages_removed: List[str]
    pages_unchanged: List[str]
    average_score_delta: int
    page_score_changes: List[CrawlPageDiff] = Field(default_factory=list)
