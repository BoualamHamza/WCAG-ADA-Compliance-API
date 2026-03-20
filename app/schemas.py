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


class ScanRequest(BaseModel):
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
