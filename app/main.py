from fastapi import BackgroundTasks, FastAPI, HTTPException

from app.scanner import (
    cancel_crawl_job,
    create_crawl_job,
    create_rule_set,
    get_audit_log,
    get_audit_logs,
    get_crawl_job,
    get_rule_set,
    get_rule_reference,
    get_rule_sets,
    get_supported_rules,
    get_supported_standards,
    process_crawl_job,
    retry_webhook_delivery,
    run_batch_scan,
    run_crawl_diff,
    run_diff_scan,
    run_scan,
)
from app.schemas import (
    AuditLogEntry,
    AuditLogsResponse,
    BatchScanRequest,
    BatchScanResponse,
    CrawlDiffRequest,
    CrawlDiffResponse,
    CrawlJobRequest,
    CrawlJobResponse,
    RetryWebhookResponse,
    RuleReference,
    RuleSetCreateRequest,
    RuleSetResponse,
    RuleSetsResponse,
    RulesResponse,
    ScanDiffRequest,
    ScanDiffResponse,
    ScanRequest,
    ScanResponse,
    StandardsResponse,
)

app = FastAPI(title="AccessCheck API", version="0.8.1")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
def scan(payload: ScanRequest) -> ScanResponse:
    try:
        return run_scan(payload)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="Rule set not found") from error
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@app.post("/scan/batch", response_model=BatchScanResponse)
def scan_batch(payload: BatchScanRequest) -> BatchScanResponse:
    webhook_url = str(payload.webhook_url) if payload.webhook_url else None
    try:
        return run_batch_scan(payload.scans, webhook_url=webhook_url)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="Rule set not found") from error
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@app.post("/scan/batch/{delivery_id}/retry", response_model=RetryWebhookResponse)
def retry_batch_callback(delivery_id: str) -> RetryWebhookResponse:
    try:
        return retry_webhook_delivery(delivery_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="Webhook delivery not found") from error


@app.post("/scan/diff", response_model=ScanDiffResponse)
def scan_diff(payload: ScanDiffRequest) -> ScanDiffResponse:
    return run_diff_scan(payload.baseline, payload.current)


@app.post("/jobs", response_model=CrawlJobResponse, status_code=202)
def create_job(payload: CrawlJobRequest, background_tasks: BackgroundTasks) -> CrawlJobResponse:
    try:
        job = create_crawl_job(payload)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="Rule set not found") from error
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    background_tasks.add_task(process_crawl_job, job.job_id)
    return job


@app.get("/jobs/{job_id}", response_model=CrawlJobResponse)
def get_job(job_id: str) -> CrawlJobResponse:
    try:
        return get_crawl_job(job_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="Job not found") from error


@app.delete("/jobs/{job_id}", response_model=CrawlJobResponse)
def cancel_job(job_id: str) -> CrawlJobResponse:
    try:
        return cancel_crawl_job(job_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="Job not found") from error


@app.post("/jobs/diff", response_model=CrawlDiffResponse)
def crawl_diff(payload: CrawlDiffRequest) -> CrawlDiffResponse:
    try:
        return run_crawl_diff(payload.baseline_job_id, payload.current_job_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="Job not found") from error
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


@app.get("/rules", response_model=RulesResponse)
def rules() -> RulesResponse:
    return get_supported_rules()


@app.get("/standards", response_model=StandardsResponse)
def standards() -> StandardsResponse:
    return get_supported_standards()


@app.get("/rules/{rule_id}", response_model=RuleReference)
def rule_detail(rule_id: str) -> RuleReference:
    try:
        return get_rule_reference(rule_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="Rule not found") from error


@app.get("/rule-sets", response_model=RuleSetsResponse)
def list_rule_sets() -> RuleSetsResponse:
    return get_rule_sets()


@app.post("/rule-sets", response_model=RuleSetResponse, status_code=201)
def create_custom_rule_set(payload: RuleSetCreateRequest) -> RuleSetResponse:
    try:
        return create_rule_set(payload)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@app.get("/rule-sets/{rule_set_id}", response_model=RuleSetResponse)
def get_custom_rule_set(rule_set_id: str) -> RuleSetResponse:
    try:
        return get_rule_set(rule_set_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="Rule set not found") from error


@app.get("/audit-logs", response_model=AuditLogsResponse)
def list_audit_logs() -> AuditLogsResponse:
    return get_audit_logs()


@app.get("/audit-logs/{event_id}", response_model=AuditLogEntry)
def audit_log_detail(event_id: str) -> AuditLogEntry:
    try:
        return get_audit_log(event_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="Audit log not found") from error
