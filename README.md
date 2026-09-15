# ChainSentry - Software Supply Chain Security Analyzer

> Automated Supply Chain Risk Engine | Dependency DAG Reasoning | Attack Indicator Detection | AI-Powered Remediation

ChainSentry is an enterprise-grade static security analyzer for software supply chains. It scans polyglot repositories across npm, PyPI, Maven, Go, and Cargo to detect vulnerabilities, typosquatting, suspicious package behavior, and CI/CD tampering — all with a **Zero Code Execution Guarantee**.

---

## What ChainSentry Does

ChainSentry runs a multi-stage static analysis pipeline on any repository:

1. **Ecosystem Detection** — discovers all manifest files across supported package managers
2. **Dependency Parsing** — extracts declared and transitive dependencies without invoking any package manager
3. **Vulnerability Lookup** — live correlation against [OSV.dev](https://osv.dev) with offline fallback
4. **Typosquatting & Confusion Detection** — Unicode homoglyph attacks, separator tricks, combosquatting, namespace collisions
5. **Reputation Analysis** — flags newly published packages, version spikes, deprecated libraries, disposable author domains
6. **Build Provenance Auditing** — inspects GitHub Actions workflows for unpinned actions and dangerous permissions; AST-scans `setup.py` for backdoors
7. **Lifecycle Script Analysis** — detects malicious npm pre/post-install hooks
8. **Dependency Graph** — builds a NetworkX DAG with blast-radius calculations per package
9. **Risk Scoring** — deterministic 0-100 security score with P0–P3 priority tiers
10. **AI Remediation** — generates plain-English attack narratives and ready-to-apply Git diff patches (Gemini + deterministic fallback)

---

## Security Capabilities

| Capability | Module | Details |
|---|---|---|
| Dependency Graph | `backend.graph` | NetworkX DAG, multi-hop transitive chains, blast-radius propagation from `package-lock.json` v1/v2/v3 |
| Known Vulnerabilities | `backend.scanner.osv` | Live OSV.dev batch API across npm, PyPI, Maven, Go, Cargo; CVSS scoring; offline fallback |
| Typosquatting & Confusion | `backend.scanner.heuristics` | 150+ popular packages, Unicode confusables, separator tricks (`_` vs `-`), combosquatting, namespace collisions |
| Package Reputation | `backend.scanner.reputation` | Freshness (< 14 days), version jump spikes (>= 50.0.0), deprecated packages, disposable author domains |
| Build Provenance | `backend.scanner.provenance` | Unpinned Actions, `permissions: write-all`, `curl \| bash`, `pull_request_target`, AST-based `setup.py` inspection |
| Prioritized Remediation | `backend.remediation` & `backend.ai` | P0–P3 tiers, CycloneDX v1.5 SBOM, SARIF v2.1.0, CI/CD quality gate, AI-generated Git diff patches |

---

## Zero Code Execution Guarantee

ChainSentry **never executes untrusted code** from scanned repositories:

- All analysis is 100% static — AST inspection, JSON/TOML decoders, and regex matching only
- No `npm install`, `pip install`, `setup.py develop`, or `eval()` is ever triggered
- ZIP archives are sandboxed with Zip Slip protection and size limits (50 MB upload / 100 MB extracted)
- Safe against malicious code bombs in attacker-controlled repositories

---

## Quick Start

### 1. Install

```bash
git clone https://github.com/your-org/chainsentry.git
cd chainsentry
pip install -r requirements.txt
```

### 2. CLI

```bash
# Scan a local repository and print the findings summary
python -m backend.cli ./demo-repository

# Export CycloneDX SBOM and SARIF report
python -m backend.cli ./demo-repository --sbom sbom.cdx.json --sarif results.sarif

# CI/CD Quality Gate — exits 1 on P0/Critical findings, 0 on clean
python -m backend.cli ./demo-repository --gate
```

### 3. API Server

```bash
uvicorn backend.main:app --reload
```

The server starts at `http://127.0.0.1:8000`. Key routes:

- `/` — landing page
- `/dashboard` — security analyzer UI
- `/docs` — interactive OpenAPI docs

---

## REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/scans` | Scan a GitHub URL or local directory |
| `POST` | `/api/v1/scans/upload` | Scan a `.zip` archive |
| `GET` | `/api/v1/scans/{id}` | Poll scan status and progress |
| `GET` | `/api/v1/scans/{id}/results` | Full findings, dependencies, risk score |
| `GET` | `/api/v1/scans/{id}/graph` | Dependency DAG with blast radius per node |
| `GET` | `/api/v1/scans/{id}/sbom.cdx.json` | NTIA-compliant CycloneDX v1.5 SBOM |
| `GET` | `/api/v1/scans/{id}/sarif` | SARIF v2.1.0 for GitHub Code Scanning |
| `POST` | `/api/v1/scans/{id}/gate` | Evaluate CI/CD quality gate policy |
| `POST` | `/api/v1/scans/{id}/explain` | AI threat narrative + auto-patch diff |
| `GET` | `/health` | Service health and scanner capabilities |

---

## Configuration

Copy `.env.example` to `.env` and set your values.

| Variable | Default | Description |
|---|---|---|
| `APP_ENV` | `development` | `development` or `production` |
| `SECRET_KEY` | *(change this)* | Always override in production |
| `CORS_ORIGINS` | `*` | Comma-separated allowed origins |
| `GITHUB_TOKEN` | — | GitHub PAT for private repo scanning |
| `GEMINI_API_KEY` | — | Google Gemini key for AI explanations |
| `FIREBASE_CREDENTIALS_PATH` | — | Firebase service account JSON path |
| `MAX_UPLOAD_SIZE_BYTES` | `52428800` | Max ZIP size (50 MB) |
| `SCAN_TIMEOUT_SECONDS` | `180` | Max scan execution time |

When `GEMINI_API_KEY` is not set, ChainSentry falls back to the deterministic expert reasoning engine. No API key is needed for core scanning.

---

## Project Structure

```
chainsentry/
├── backend/
│   ├── main.py              # FastAPI app factory
│   ├── config.py            # Typed settings (Pydantic)
│   ├── pipeline/            # Scan orchestrator
│   ├── ingestion/           # GitHub clone + ZIP extraction
│   ├── ecosystems/          # Manifest detection
│   ├── parsers/             # Static dependency parsers
│   ├── scanner/             # Vuln, heuristics, reputation, provenance, lifecycle
│   ├── graph/               # NetworkX dependency DAG
│   ├── remediation/         # SBOM, SARIF, CI gate
│   ├── ai/                  # AI explainer (Gemini + fallback)
│   ├── database/            # Firebase + in-memory store
│   ├── routers/             # FastAPI endpoints
│   ├── models/              # Domain models
│   ├── schemas/             # Pydantic API schemas
│   └── security/            # Subprocess allowlist, policy enforcement
├── frontend/                # Static HTML/CSS/JS dashboard
├── tests/                   # 184 automated tests
├── demo-repository/         # Sample repo with known findings
└── scripts/                 # Build utilities
```

---

## Supported Ecosystems

| Ecosystem | Manifest Files |
|---|---|
| Node.js / npm | `package.json`, `package-lock.json` |
| Python / PyPI | `requirements.txt`, `pyproject.toml`, `setup.py` |
| Java / Maven | `pom.xml` |
| Go | `go.mod`, `go.sum` |
| Rust / Cargo | `Cargo.toml`, `Cargo.lock` |

---

## Testing

```bash
python -m pytest
```

184 tests covering parsers, scanners, APIs, CLI, and end-to-end scan workflows.

---

## Output Formats

- **CycloneDX v1.5 JSON SBOM** — NTIA minimum element compliant software bill of materials
- **SARIF v2.1.0** — integrates with GitHub Security tab and CI pipeline alert systems
- **CI/CD Quality Gate** — returns exit code `0` (clean) or `1` (P0/Critical findings)
- **AI Threat Report** — executive summary, attack scenario narratives, and unified Git diff patches

---

## License

MIT
