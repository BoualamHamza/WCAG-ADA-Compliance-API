# Project Progress Tracker

## Phase 1 — MVP (completed)

### Completed
- Set up initial FastAPI service skeleton.
- Implemented `POST /scan` endpoint with URL and HTML input modes.
- Added compliance scoring and POUR score breakdown.
- Added mandatory coverage disclaimer in responses.
- Added unit tests for health and scan behaviors.
- Added Phase 2 kickoff endpoints for `POST /scan/batch` and `GET /rules`.

## Phase 2 — Completed

### Completed
- Batch scan orchestration via `POST /scan/batch` with combined results and average score.
- Rules reference endpoint via `GET /rules` to expose supported checks.
- AI remediation detail levels (`brief`, `standard`, `verbose`) and locale support for localized guidance.
- Added persistence for queued webhook deliveries and retry tracking with `POST /scan/batch/{delivery_id}/retry`.
- Expanded pass/incomplete findings to include structured rule metadata (`wcag_sc`, `impact`) and confidence scores.

## Phase 3 — Completed

### Completed this phase
- Added `POST /scan/diff` endpoint to compare baseline/current scans and report score deltas plus violation changes.
- Added async crawl job lifecycle support with `POST /jobs`, `GET /jobs/{job_id}`, and `DELETE /jobs/{job_id}`.
- Added live URL fetching for public site scans so URL mode analyzes retrieved HTML instead of only the URL string.
- Added discovered route inventory diffing with `POST /jobs/diff` and average score delta reporting for completed crawl jobs.
- Expanded crawl configuration with `max_depth`, `allowed_path_prefixes`, and `excluded_path_prefixes`.
- Added richer crawl metadata with per-page depth/parent tracking and per-page score delta summaries in crawl diffs.
- Added live test coverage against real public brand websites in addition to deterministic mocked tests.
- Added crawl politeness controls for `respect_robots_txt`, `request_delay_ms`, and custom `user_agent` handling.
- Added crawl concurrency control via `max_concurrency` and richer per-page diff details for new/resolved violations on matching routes.

## Upcoming Phases
- **Phase 4:** Enterprise controls and integrations.

## Delivery Log
- Phase 1 checkpoint committed.
- Phase 2 kickoff in progress with batch and rules endpoints.
- Added remediation detail levels and locale-aware remediation messaging for scan output.
- Added optional webhook callback registration metadata for batch scans.
- Expanded scan response payload with structured `passes` and `incomplete` arrays.
- Added webhook delivery persistence with retry history tracking.
- Started Phase 3 with scan diff capabilities.
- Completed async crawl jobs lifecycle endpoints and in-memory job tracking.
- Extended Phase 3 with live website fetching and crawl route inventory diff support.
- Added configurable crawl depth/path filters, page-level crawl metadata, and live public-brand-site test coverage.
- Completed Phase 3 with crawl politeness/concurrency controls and violation-level page diff reporting.
