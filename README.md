<div align="center">

# ChainSentry

**Software Supply Chain Security Analyzer**

Automated dependency risk engine with vulnerability detection, typosquatting analysis, build provenance auditing, and AI-powered remediation — across every major package ecosystem.

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Tests](https://img.shields.io/badge/Tests-184%20passing-22c55e?style=flat-square)](./tests)
[![License](https://img.shields.io/badge/License-MIT-6366f1?style=flat-square)](./LICENSE)
[![Zero Execution](https://img.shields.io/badge/Code%20Execution-Zero-ef4444?style=flat-square)](#zero-code-execution-guarantee)

</div>

---

## Overview

ChainSentry performs **fully static security analysis** on software repositories. It never installs packages, never runs scripts, and never executes untrusted code — making it safe to point at any repository, including adversarial ones.

It supports **npm, PyPI, Maven, Go, and Cargo** in a single scan pass, producing prioritized findings, a dependency graph with blast-radius calculations, a CycloneDX SBOM, a SARIF report for CI/CD integration, and AI-generated remediation patches.

---

## How the Scan Works

```
Repository (GitHub URL / ZIP / Local Path)
        │
        ▼
  ┌─────────────────────────────────────────────────────┐
  │  1  Ecosystem Detection    (manifest discovery)      │
  │  2  Dependency Parsing     (static, no pkg manager)  │
  │  3  Lockfile Resolution    (transitive deps)         │
  │  4  Dependency Graph       (NetworkX DAG)            │
  │  5  OSV Vulnerability Scan (live + offline fallback) │
  │  6  Typosquatting Check    (Unicode, edit distance)  │
  │  7  Reputation Analysis    (age, version, author)    │
  │  8  Provenance Audit       (CI/CD, setup.py AST)     │
  │  9  Lifecycle Script Scan  (npm hooks)               │
  │  10 Risk Scoring           (0-100, P0-P3 tiers)      │
  │  11 AI Remediation         (Gemini / expert fallback)│
  └─────────────────────────────────────────────────────┘
        │
        ▼
   Findings  ·  SBOM  ·  SARIF  ·  Graph  ·  AI Patch
```

---

## Security Capabilities

| # | Capability | What It Catches |
|---|---|---|
| 1 | **Known Vulnerabilities** | Live CVE lookup via OSV.dev across all ecosystems, CVSS scoring, offline fallback |
| 2 | **Dependency Graph** | NetworkX DAG with multi-hop transitive chains, ancestor blast-radius, propagation paths |
| 3 | **Typosquatting & Confusion** | Unicode homoglyphs, separator tricks (`_` vs `-`), combosquatting, internal namespace hijacking |
| 4 | **Package Reputation** | Packages < 14 days old, version spikes (>= 50.0.0), deprecated libraries, disposable author emails |
| 5 | **Build Provenance** | Unpinned GitHub Actions, `permissions: write-all`, `curl \| bash` pipes, `pull_request_target` misuse |
| 6 | **AST Backdoor Detection** | Python `setup.py` inspected for reverse shells, encoded payloads, subprocess abuse |
| 7 | **Lifecycle Scripts** | npm `postinstall`/`prepare` hooks scanned for network downloads and eval patterns |
| 8 | **Prioritized Remediation** | P0–P3 tiers, CycloneDX SBOM, SARIF v2.1.0, CI/CD gate, AI-generated unified diff patches |

---

## Zero Code Execution Guarantee

> ChainSentry is safe to run against any repository, including attacker-controlled ones.

- **No package manager is ever invoked** — no `npm install`, `pip install`, `cargo build`, or `mvn package`
- **No code is evaluated** — no `eval()`, `exec()`, or subprocess spawning from scanned content
- **All parsing is static** — JSON/TOML/XML decoders, AST visitors, and regex only
- **ZIP extraction is sandboxed** — Zip Slip protection, 50 MB upload limit, 100 MB extraction cap, per-file 10 MB limit

---

## Quick Start

### Prerequisites

- Python 3.10+
- pip

### Install

```bash
git clone https://github.com/your-org/chainsentry.git
cd chainsentry
pip install -r requirements.txt
```

### Scan via CLI

```bash
# Print findings summary to terminal
python -m backend.cli ./demo-repository

# Export CycloneDX SBOM + SARIF report
python -m backend.cli ./demo-repository --sbom sbom.cdx.json --sarif results.sarif

# CI/CD Quality Gate (exit 1 on any P0/Critical finding)
python -m backend.cli ./demo-repository --gate
```

### Run the API Server

```bash
uvicorn backend.main:app --reload
```

| URL | Page |
|---|---|
| `http://127.0.0.1:8000/` | Landing page |
| `http://127.0.0.1:8000/dashboard` | Security analyzer dashboard |
| `http://127.0.0.1:8000/docs` | Interactive API docs (Swagger) |

---

## REST API

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/scans` | Scan a GitHub URL or local directory |
| `POST` | `/api/v1/scans/upload` | Scan a `.zip` archive |
| `GET` | `/api/v1/scans/{id}` | Poll scan status and progress percentage |
| `GET` | `/api/v1/scans/{id}/results` | Full findings, dependencies, and risk score |
| `GET` | `/api/v1/scans/{id}/graph` | Dependency DAG with blast radius per node |
| `GET` | `/api/v1/scans/{id}/sbom.cdx.json` | NTIA-compliant CycloneDX v1.5 SBOM |
| `GET` | `/api/v1/scans/{id}/sarif` | SARIF v2.1.0 report for GitHub Code Scanning |
| `POST` | `/api/v1/scans/{id}/gate` | Evaluate scan against a CI/CD quality gate policy |
| `POST` | `/api/v1/scans/{id}/explain` | AI threat narrative and auto-patch diff |
| `GET` | `/health` | Service health, uptime, and scanner capabilities |

### Example: Scan a GitHub repository

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/expressjs/express"}'
```

### Example: Fetch results

```bash
curl http://127.0.0.1:8000/api/v1/scans/{scan_id}/results
```

---

## Configuration

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `APP_ENV` | `development` | `development` or `production` |
| `SECRET_KEY` | — | **Required in production** — override the insecure default |
| `CORS_ORIGINS` | `*` | Comma-separated allowed origins for the API |
| `GITHUB_TOKEN` | — | GitHub PAT to clone private repositories |
| `GEMINI_API_KEY` | — | Google Gemini key for AI-powered explanations |
| `FIREBASE_CREDENTIALS_PATH` | — | Path to a Firebase service account JSON file |
| `MAX_UPLOAD_SIZE_BYTES` | `52428800` | Maximum ZIP upload size (default 50 MB) |
| `SCAN_TIMEOUT_SECONDS` | `180` | Hard timeout on scan execution (default 3 min) |

> **No API key required for core scanning.** When `GEMINI_API_KEY` is absent, ChainSentry uses its built-in deterministic expert engine for threat explanations and patch generation.

---

## Supported Ecosystems

| Ecosystem | Parsed Files |
|---|---|
| **Node.js / npm** | `package.json`, `package-lock.json` (v1/v2/v3) |
| **Python / PyPI** | `requirements.txt`, `pyproject.toml`, `setup.py` |
| **Java / Maven** | `pom.xml` |
| **Go** | `go.mod`, `go.sum` |
| **Rust / Cargo** | `Cargo.toml`, `Cargo.lock` |

---

## Output Formats

| Format | Standard | Use Case |
|---|---|---|
| **CycloneDX SBOM** | v1.5 JSON | Software bill of materials, NTIA minimum elements |
| **SARIF Report** | v2.1.0 | GitHub Security tab, CI/CD alert pipelines |
| **Quality Gate** | Exit codes 0/1 | Block failing builds in CI pipelines |
| **AI Threat Report** | — | Executive narrative, attack scenarios, unified Git diff |

---

## Risk Scoring

Each scan produces a **security score from 0 to 100** and a **risk level**:

| Score | Risk Level | Meaning |
|---|---|---|
| 90 – 100 | `SAFE` | No significant issues found |
| 75 – 89 | `LOW` | Minor signals, low urgency |
| 50 – 74 | `MEDIUM` | Notable findings, review recommended |
| 25 – 49 | `HIGH` | Serious issues, prompt action needed |
| 0 – 24 | `CRITICAL` | Active attack indicators, immediate action required |

Findings are further bucketed into **P0–P3 priority tiers** for remediation ordering.

---

## Project Structure

```
chainsentry/
├── backend/
│   ├── main.py                  # FastAPI app factory and lifespan
│   ├── config.py                # Pydantic settings, env resolution
│   ├── exceptions.py            # Typed exception hierarchy
│   ├── error_handlers.py        # Centralized error responses
│   ├── pipeline/
│   │   └── orchestrator.py      # 11-stage scan pipeline coordinator
│   ├── ingestion/
│   │   ├── git_cloner.py        # GitHub repository cloner
│   │   ├── zip_extractor.py     # Sandboxed ZIP extraction
│   │   └── workspace.py        # Workspace abstraction
│   ├── ecosystems/
│   │   ├── detector.py          # Manifest file discovery
│   │   └── inventory.py        # Manifest type inventory
│   ├── parsers/                 # One static parser per format
│   │   ├── package_json.py
│   │   ├── lockfiles.py
│   │   ├── python_deps.py
│   │   ├── maven.py
│   │   ├── go_mod.py
│   │   └── cargo_toml.py
│   ├── scanner/
│   │   ├── osv.py               # OSV.dev vulnerability lookup
│   │   ├── heuristics.py        # Typosquatting and confusion
│   │   ├── reputation.py        # Package reputation signals
│   │   ├── provenance.py        # CI/CD and setup.py audit
│   │   ├── lifecycle.py         # npm lifecycle hook scanner
│   │   └── risk_engine.py       # Scoring and P0-P3 prioritization
│   ├── graph/
│   │   └── dependency_graph.py  # NetworkX DAG + blast radius
│   ├── remediation/
│   │   ├── sbom.py              # CycloneDX v1.5 generator
│   │   ├── sarif.py             # SARIF v2.1.0 generator
│   │   └── gate.py              # CI/CD quality gate evaluator
│   ├── ai/
│   │   └── explainer.py         # Gemini + deterministic fallback
│   ├── database/
│   │   ├── firebase.py          # Firestore client
│   │   └── repository.py        # Scan store (Firebase or in-memory)
│   ├── routers/
│   │   ├── scans.py             # Scan ingestion and results endpoints
│   │   └── health.py            # Health check endpoint
│   ├── models/                  # Pydantic domain models
│   └── schemas/                 # API request/response schemas
├── frontend/                    # Static HTML/CSS/JS dashboard
├── tests/                       # 184 automated tests
├── demo-repository/             # Benchmark repo with planted findings
└── scripts/                     # Build and utility scripts
```

---

## Testing

```bash
# Run all tests
python -m pytest

# Run with verbose output
python -m pytest -v

# Run a specific test file
python -m pytest tests/test_scan_orchestrator.py
```

The test suite covers parsers, all scanner modules, API endpoints, CLI, the dependency graph, SBOM/SARIF generation, and end-to-end scan workflows.

---

## License

MIT — see [LICENSE](./LICENSE)
