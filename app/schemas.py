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


class PourBreakdown(BaseModel):
    perceivable: int
    operable: int
    understandable: int
    robust: int


class ScanResponse(BaseModel):
    scan_mode: ScanMode
    target: str
    violations: List[Violation]
    totals: dict
    score: int
    pour_breakdown: PourBreakdown
    static_scan_warning: bool = False
    coverage_disclaimer: str


class BatchScanRequest(BaseModel):
    scans: List[ScanRequest] = Field(min_length=1, max_length=10)


class BatchScanResponse(BaseModel):
    total_scans: int
    average_score: int
    results: List[ScanResponse]


class RuleReference(BaseModel):
    rule_id: str
    description: str
    wcag_sc: str
    impact: str


class RulesResponse(BaseModel):
    count: int
    rules: List[RuleReference]
