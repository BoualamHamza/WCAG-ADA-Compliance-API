from fastapi import FastAPI, HTTPException

from app.scanner import get_supported_rules, retry_webhook_delivery, run_batch_scan, run_diff_scan, run_scan
from app.schemas import (
    BatchScanRequest,
    BatchScanResponse,
    RetryWebhookResponse,
    RulesResponse,
    ScanDiffRequest,
    ScanDiffResponse,
    ScanRequest,
    ScanResponse,
)

app = FastAPI(title="AccessCheck API", version="0.3.0")


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


@app.get("/rules", response_model=RulesResponse)
def rules() -> RulesResponse:
    return get_supported_rules()
