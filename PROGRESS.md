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

## Phase 3 — In progress

### Started
- Added `POST /scan/diff` endpoint to compare baseline/current scans and report score deltas plus violation changes.

### Next in Phase 3
- Async crawl jobs lifecycle endpoints and in-memory job state.
- Diff support for crawled route inventories.

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
