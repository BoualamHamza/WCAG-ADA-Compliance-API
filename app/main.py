from fastapi import FastAPI

from app.scanner import get_supported_rules, run_batch_scan, run_scan
from app.schemas import BatchScanRequest, BatchScanResponse, RulesResponse, ScanRequest, ScanResponse

app = FastAPI(title="AccessCheck API", version="0.2.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
def scan(payload: ScanRequest) -> ScanResponse:
    return run_scan(payload)


@app.post("/scan/batch", response_model=BatchScanResponse)
def scan_batch(payload: BatchScanRequest) -> BatchScanResponse:
    return run_batch_scan(payload.scans)


@app.get("/rules", response_model=RulesResponse)
def rules() -> RulesResponse:
    return get_supported_rules()
