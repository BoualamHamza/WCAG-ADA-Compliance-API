# WCAG-ADA-Compliance-API

Developer-first API to audit URLs or HTML snippets for accessibility issues aligned with WCAG/ADA-focused reporting.

## Current Status

Implemented so far:
- FastAPI service with:
  - `GET /health`
  - `POST /scan` (URL mode + HTML mode)
  - `POST /scan/batch` (multi-target kickoff for Phase 2)
  - `GET /rules` (supported rule catalog)
- Structured JSON response with:
  - violations
  - totals
  - score (0-100)
  - POUR breakdown
  - static scan warning
  - legal coverage disclaimer
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
pytest -q
```
