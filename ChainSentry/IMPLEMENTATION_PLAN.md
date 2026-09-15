# Implementation Plan

## Project Status

Previous milestones: 01–25 (original roadmap; **not all implemented in git**)
Current milestone: 28
Completed new milestones: 2/25 (26–27 done)
In progress: none
Remaining: 28–50
Blocked: 0

## Deadline Mode

ACTIVE

Priority:
Working project > completeness > polish > architectural perfection

## Repository audit (2026-09-11)

### Git

- Branch: `main` tracking `origin/main`
- Latest commit: `564a6ac` — refined the lockfile inventory
- Uncommitted: `backend/parsers/` and `tests/test_package_json_parser.py` (static package.json parser from prompts 023/024; **not in git yet**)
- ~11 meaningful commits after the clean-slate commit, **not** 25 completed product stages

### What actually exists

| Original stage | Status | Reality |
|---|---|---|
| 1 Foundation | ✅ COMPLETED | FastAPI app factory, config, CORS, logging (`backend/main.py`, `backend/config.py`) |
| 2 Firestore | ✅ COMPLETED | Firebase optional init + `ScanRepository` with in-memory fallback |
| 3 API/error | ✅ COMPLETED | Typed exceptions + handlers (`backend/exceptions.py`, `backend/error_handlers.py`) |
| 4 GitHub ingestion | 🔄 IN PROGRESS | `GitCloner` + URL validator + tests. **No** `POST /scans` GitHub route |
| 5 ZIP ingestion | 🔄 IN PROGRESS | `POST /api/v1/scans/upload` extracts ZIP and creates PENDING scan. **Does not analyze** |
| 6 Untrusted security | ✅ COMPLETED | Policy, allowlisted subprocess runner, zip-slip tests, no npm/pip install |
| 7 Ecosystem detection | ✅ COMPLETED | Manifest inventory + detector + fixtures |
| 8 Node dependencies | 🔄 IN PROGRESS | Static `package.json` parser exists locally, uncommitted, **not wired to scans** |
| 9 Multi-ecosystem deps | ⏳ NOT STARTED | Inventory finds Python/Go/Maven/Cargo files; no parsers |
| 10 NetworkX graph | ⏳ NOT STARTED | Graph **response schemas** exist only |
| 11 Graph impact/API | ⏳ NOT STARTED | |
| 12 OSV | ⏳ NOT STARTED | Config URL + health “osv-scanner” binary check only |
| 13 Vuln correlation | ⏳ NOT STARTED | |
| 14 Syft + Grype | ⏳ NOT STARTED | Health/capability flags only; never invoked |
| 15 Typosquatting | ⏳ NOT STARTED | Enum + schema mention only |
| 16 Dependency confusion | ⏳ NOT STARTED | |
| 17 Suspicious behavior | ⏳ NOT STARTED | |
| 18 Static source analysis | ⏳ NOT STARTED | setup.py AST name/version only |
| 19 Reputation | ⏳ NOT STARTED | |
| 20–21 Provenance | ⏳ NOT STARTED | Domain models only |
| 22 Risk engine | ⏳ NOT STARTED | `RiskAssessment` model only |
| 23 Prioritization/remediation | ⏳ NOT STARTED | Enums/fields only |
| 24 Orchestrator | ⏳ NOT STARTED | ZIP upload stops at PENDING |
| 25 Scan API | 🔄 IN PROGRESS | Upload only. No GET status, no GET results, no GitHub create |

### Empty / missing product surfaces

- `frontend/` — empty (no dashboard)
- `docs/` — empty
- `demo-repository/` — empty
- `scripts/` — empty
- No root `requirements.txt` / `pyproject.toml` — **backend is not installable as documented**
- No scan orchestrator, OSV client, graph builder, report generator, or Grok usage

### APIs that work today

- `GET /` metadata
- `GET /health` (app + optional Firebase + binary presence)
- `POST /api/v1/scans/upload` (ingest ZIP → persist PENDING scan)

### APIs that do not exist

- GitHub scan create
- Scan status polling
- Scan detail (deps, findings, risk, graph, report)
- Findings / graph / report routes

### Known issues

- Upload creates a scan and extracts a workspace, then **never runs analysis**; workspace is not stored on the scan document for later use
- `GitHubScanRequest` schema exists but is unused by any router
- External scanners advertised in health are not integrated
- Frontend cannot be opened
- No demo corpus with guaranteed findings
- App dependencies are not pinned in-repo (pytest/pydantic/fastapi assumed)

## Fastest path to a demonstrable system

```text
Installable backend
  → land package.json parser
  → Python declared-deps parser
  → orchestrator (ingest → detect → parse → persist)
  → GitHub + ZIP both start scans
  → GET status + GET detail
  → demo repo
  → OSV (HTTP, degrade if down)
  → simple risk
  → declared-dep graph
  → static heuristics (typosquat / lifecycle scripts)
  → vanilla frontend
  → report
  → e2e + docs + security pass
```

Skip for deadline unless leftover time: Syft/Grype CLI, Grok explanations, full provenance, reputation APIs, lockfile resolution.

## Current milestone

28 — Static Python declared-dependency parser

## Next milestone

29 — Scan orchestrator skeleton

## Exact next action

Implement Prompt 28: static `requirements.txt` / `pyproject.toml` parsers, then Prompt 29 orchestrator.

## Milestone log

### 01–25 — Original roadmap vs git

Status: ⚠️ BLOCKED as a “completed 25” claim — **do not treat original 01–25 as done**

Git commits that map to real work:

- `99c88b6` backend foundation
- `9c7677b` firebase
- `dd21c67` API errors
- `00add22` GitHub intake
- `abc47c5` ZIP intake
- `3c3308b` / `0a29729` / `564a6ac` ecosystems + fixtures + lockfile inventory

### 26 — Backend runtime bootstrap

Status: ✅ COMPLETED

### Changes

- Added `requirements.txt` and `pytest.ini` (`pythonpath = .`)
- Documented venv install + uvicorn in README
- Added `GROK_API_KEY` to `.env.example`
- Imported `Optional` in `backend/config.py`
- Added persistent `IMPLEMENTATION_PLAN.md` and `NEXT_25_PROMPTS.md`

### Tests

- Health + API schema tests: PASS (with local venv)

### Commit

`feat(26): add backend runtime dependencies and pytest config`

### Next

27 — Land static package.json parser

### 27 — Land static package.json parser

Status: ✅ COMPLETED

### Changes

- Added JSON-only `backend/parsers` for package.json
- Nested/workspace discovery without npm
- Unit tests for sections, malformed JSON, empty deps, nested trees

### Tests

- `tests/test_package_json_parser.py`: PASS

### Commit

`feat(27): add static package.json dependency parser`

### Next

28 — Static Python declared-dependency parser
