# WCAG-ADA-Compliance-API

Developer-first API to audit URLs or HTML snippets for accessibility issues aligned with WCAG/ADA-focused reporting.

## Current Status

Implemented so far:
- FastAPI service with:
  - `GET /health`
  - `POST /scan` (URL mode + HTML mode, with live HTML fetch for public URLs)
  - `POST /scan/batch` (multi-target scans + optional webhook callback registration)
  - `POST /scan/batch/{delivery_id}/retry` (retry tracking for queued webhook deliveries)
  - `POST /scan/diff` (Phase 3 diff endpoint for baseline/current scan deltas)
  - `POST /jobs` (create async crawl jobs)
  - `GET /jobs/{job_id}` (poll crawl job status and results)
  - `DELETE /jobs/{job_id}` (cancel queued or running crawl jobs)
  - `POST /jobs/diff` (compare crawled route inventories and average score movement)
  - `GET /rules` (supported rule catalog)
- Structured JSON response with:
  - violations
  - passes (rule metadata + confidence)
  - incomplete (rule metadata + confidence)
  - totals
  - score (0-100)
  - POUR breakdown
  - static scan warning
  - legal coverage disclaimer
- In-memory webhook delivery persistence and retry history tracking.
- In-memory crawl job lifecycle tracking with discovered route inventory summaries and scan results.
- Initial unit tests with `pytest`
- Progress tracking in [`PROGRESS.md`](./PROGRESS.md)

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Run tests:

```bash
PYTHONPATH=. pytest -q
```
