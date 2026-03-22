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
  - `GET /standards` (supported compliance standards catalog)
  - `GET /rules/{rule_id}` (single rule detail lookup)
  - `GET /rule-sets` / `POST /rule-sets` / `GET /rule-sets/{rule_set_id}` (custom enterprise rule set management with effective rule resolution)
  - `GET /audit-logs` / `GET /audit-logs/{event_id}` (enterprise audit trail for scans, jobs, rule sets, and webhook registrations)
- Enterprise rule targeting with `run_only`, `disable_rules`, and reusable `rule_set_id` references across scans and crawl jobs, including validation that at least one effective rule remains.
- Standards metadata on the rule catalog plus a dedicated standards catalog covering WCAG, Section 508, EAA, and best-practice tags.
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
- Crawl controls for `max_depth`, `max_concurrency`, `respect_robots_txt`, `request_delay_ms`, custom `user_agent`, allowed path prefixes, and excluded path prefixes.
- Per-page crawl result metadata (`url`, `depth`, `parent_url`, nested scan payload) plus crawl diff page score deltas and violation-level add/remove details.
- Initial unit tests with `pytest`
- Live integration-style tests against public brand websites (`amazon.com`, `apple.com`, `microsoft.com`) in addition to mocked coverage.
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
