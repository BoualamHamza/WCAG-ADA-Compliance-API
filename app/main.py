from fastapi import FastAPI

from app.scanner import run_scan
from app.schemas import ScanRequest, ScanResponse

app = FastAPI(title="AccessCheck API", version="0.1.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
def scan(payload: ScanRequest) -> ScanResponse:
    return run_scan(payload)
