# Project Progress Tracker

## Phase 1 — MVP (completed)

### Completed
- Set up initial FastAPI service skeleton.
- Implemented `POST /scan` endpoint with URL and HTML input modes.
- Added compliance scoring and POUR score breakdown.
- Added mandatory coverage disclaimer in responses.
- Added unit tests for health and scan behaviors.
- Added Phase 2 kickoff endpoints for `POST /scan/batch` and `GET /rules`.

## Phase 2 — In progress

### Started
- Batch scan orchestration via `POST /scan/batch` with combined results and average score.
- Rules reference endpoint via `GET /rules` to expose supported checks.

### Next in Phase 2
- AI remediation detail levels (`brief`, `standard`, `verbose`) and locale support.
- Webhook callback support for asynchronous scan notifications.
- Expand response payload to include structured `passes` and `incomplete` arrays.

## Upcoming Phases
- **Phase 3:** Async crawl jobs and diff endpoint.
- **Phase 4:** Enterprise controls and integrations.


## Delivery Log
- Phase 1 checkpoint committed.
- Phase 2 kickoff in progress with batch and rules endpoints.
