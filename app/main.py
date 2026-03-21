from fastapi import BackgroundTasks, FastAPI, HTTPException

from app.scanner import (
    cancel_crawl_job,
    create_crawl_job,
    get_crawl_job,
    get_supported_rules,
    process_crawl_job,
    retry_webhook_delivery,
    run_batch_scan,
    run_crawl_diff,
    run_diff_scan,
    run_scan,
)
from app.schemas import (
    BatchScanRequest,
    BatchScanResponse,
    CrawlDiffRequest,
    CrawlDiffResponse,
    CrawlJobRequest,
    CrawlJobResponse,
    RetryWebhookResponse,
    RulesResponse,
    ScanDiffRequest,
    ScanDiffResponse,
    ScanRequest,
    ScanResponse,
)

app = FastAPI(title="AccessCheck API", version="0.7.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
def scan(payload: ScanRequest) -> ScanResponse:
    return run_scan(payload)


@app.post("/scan/batch", response_model=BatchScanResponse)
def scan_batch(payload: BatchScanRequest) -> BatchScanResponse:
    webhook_url = str(payload.webhook_url) if payload.webhook_url else None
    return run_batch_scan(payload.scans, webhook_url=webhook_url)


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
    job = create_crawl_job(payload)
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
