# NitroGate — Complete Testing & Running Guide

> Everything runs locally. Nothing is pushed anywhere. No company repos touched.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [NitroGate Go Project — Tests & Build](#2-nitrogate-go-project)
3. [GUAC — Setup, Ingestion & Queries](#3-guac)
4. [Quality Gates — Local Testing on Any Repo](#4-quality-gates)
5. [Testing on Your Personal GitHub Repo](#5-testing-on-personal-repo)
6. [End-to-End Demo Flow](#6-end-to-end-demo-flow)
7. [Known Issues & Expected Errors](#7-known-issues)
8. [Files Changed (Nothing Pushed)](#8-files-changed)

---

## 1. Prerequisites

```bash
# Go (for nitrogate)
go version    # Go 1.22+

# Node (for quality gates)
node --version   # Node 18+
yarn --version   # Yarn 1.x

# Docker (for GUAC)
docker --version
docker compose version

# Verify everything
cd /Users/rahulxf/aflockGate && go build ./cmd/nitrogate/ && echo "Go: OK"
cd /Users/rahulxf/quality-gates && yarn install && echo "Quality Gates: OK"
docker info > /dev/null 2>&1 && echo "Docker: OK"
```

---

## 2. NitroGate Go Project

### 2.1 Run all unit tests

```bash
cd /Users/rahulxf/aflockGate
go test ./internal/... -count=1 -v
```

Expected output (all PASS):

```
=== RUN   TestSignAndVerify
--- PASS: TestSignAndVerify
=== RUN   TestTamperedPayloadFails
--- PASS: TestTamperedPayloadFails
ok  github.com/nitrogate/nitrogate/internal/attest

=== RUN   TestEvaluate_CleanPass
--- PASS: TestEvaluate_CleanPass
=== RUN   TestEvaluate_CriticalFail
--- PASS: TestEvaluate_CriticalFail
ok  github.com/nitrogate/nitrogate/internal/gate

=== RUN   TestSecretScanner_AWSKey
--- PASS: TestSecretScanner_AWSKey
=== RUN   TestNPMSupplyChainScanner_CompromisedPackage
--- PASS: TestNPMSupplyChainScanner_CompromisedPackage
=== RUN   TestNPMSupplyChainScanner_Typosquatting
--- PASS: TestNPMSupplyChainScanner_Typosquatting
... (30+ tests total)
ok  github.com/nitrogate/nitrogate/internal/scanner
```

### 2.2 Run specific test suites

```bash
# Only NPM supply chain tests
go test ./internal/scanner/ -run "NPMSupplyChain" -v

# Only attestation signing tests
go test ./internal/attest/ -v

# Only gate decision tests
go test ./internal/gate/ -v
```

### 2.3 Build the binary

```bash
cd /Users/rahulxf/aflockGate
go build -o bin/nitrogate ./cmd/nitrogate/
ls -lh bin/nitrogate   # ~9.5MB
```

### 2.4 What each scanner does (with test evidence)

**Secret Scanner** (`internal/scanner/secrets.go`):
- 17 regex patterns: AWS, GitHub PAT, Slack, Stripe, OpenAI, private keys, JWTs, DB connection strings, etc.
- Shannon entropy detection for high-randomness strings in assignments
- File allowlist support (`**/*.test.ts`, `**/*.example`)
- Redacts matched secrets — never exposes actual values

**Dependency Scanner** (`internal/scanner/deps.go`):
- Parses lockfile diffs: `package-lock.json`, `go.sum`, `requirements.txt`, `Cargo.lock`, `Gemfile.lock`
- Queries OSV.dev batch API for known vulnerabilities
- CVSS-based severity classification (Critical >= 9.0, High >= 7.0, Medium >= 4.0)

**NPM Supply Chain** (`internal/scanner/npm_supply_chain.go`):
- **Compromised check**: 16 known-bad packages (event-stream, ua-parser-js, colors, faker, node-ipc, flatmap-stream, eslint-scope, crossenv, babelcli, mongose, mariadb, lottie-player, etc.)
- **Typosquatting**: Levenshtein distance = 1 from 60+ popular packages + dash-removal, underscore swap, suffix patterns
- **Cooldown**: Queries npm registry, flags versions published within N days (default 7)
- **Install scripts**: Flags preinstall/install/postinstall hooks; escalates if they contain curl/wget/eval/base64

**Workflow Security** (`internal/scanner/workflow.go`):
- Script injection: `${{ github.event.pull_request.title }}` in `run:` blocks
- Pwn Request: `pull_request_target` trigger + `actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}`
- Unpinned actions: `uses: org/action@tag` instead of `@sha256`
- Excessive permissions: `permissions: write-all`

**License Checker** (`internal/scanner/license.go`):
- Resolves licenses via npm/PyPI registry APIs
- Classifies: permissive (allow), copyleft (warn/deny), AGPL (deny), unknown (warn)

---

## 3. GUAC

### 3.1 Start GUAC

```bash
cd /Users/rahulxf/aflockGate/deploy

# Download official compose (already done, skip if file exists)
curl -sL -o guac-demo-compose.yaml \
  https://github.com/guacsec/guac/releases/latest/download/guac-demo-compose.yaml

# Start all 6 containers
docker compose -f guac-demo-compose.yaml -p guac up -d --force-recreate
```

### 3.2 Verify GUAC is healthy

```bash
docker compose -f guac-demo-compose.yaml -p guac ps
```

You should see 6 containers, with graphql, collectsub, and guac-rest showing `(healthy)`:

```
guac-graphql-1           ... Up (healthy)   0.0.0.0:8080->8080/tcp
guac-collectsub-1        ... Up (healthy)   0.0.0.0:2782->2782/tcp
guac-guac-rest-1         ... Up (healthy)   0.0.0.0:8081->8081/tcp
guac-cd-certifier-1      ... Up
guac-depsdev-collector-1 ... Up
guac-osv-certifier-1     ... Up
```

### 3.3 Generate test data and ingest

```bash
cd /Users/rahulxf/aflockGate

# Step 1: Generate attestation + SBOM
go run test-guac/generate_attestation.go
# Output: "Generated DSSE envelope + SBOM ... Gate decision: FAIL, findings: 3"

# Step 2: Ingest ONLY the SBOM into GUAC (use test-guac/ingest/ to avoid errors)
docker run --rm --network guac_default \
  -v "$(pwd)/test-guac/ingest:/data" \
  ghcr.io/guacsec/guac:v1.0.1 \
  /opt/guac/guacone collect files /data/ \
  --gql-addr http://graphql:8080/query \
  --csub-addr collectsub:2782
```

**Expected output**: "completed ingesting 1 documents of 1" — the SBOM ingests cleanly with zero errors.

> **Why only the SBOM?** The attestation uses a test Ed25519 signature, not a real Sigstore
> identity, so GUAC's signature verification rejects it. Gate results are pushed via GraphQL
> mutations instead (next step). In production with Sigstore keyless signing, the attestation
> would also be ingested directly.

### 3.4 Add gate metadata via GraphQL mutations

```bash
# Mutation 1: Gate decision
curl -s http://localhost:8080/query \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { ingestHasMetadata(subject: {package: {packageInput: {type: \"guac\", namespace: \"pkg/myorg\", name: \"myrepo\", version: \"1.0.0\"}}}, pkgMatchType: {pkg: SPECIFIC_VERSION}, hasMetadata: {key: \"nitrogate:decision\", value: \"FAIL\", justification: \"3 findings — 2 critical (compromised event-stream, AWS key), 1 medium (lodash cooldown)\", timestamp: \"2026-03-03T07:35:00Z\", origin: \"nitrogate\", collector: \"nitrogate-v1\", documentRef: \"nitrogate-pr123\"}) }"
  }'
# Expected: {"data":{"ingestHasMetadata":"10"}}

# Mutation 2: PR metadata
curl -s http://localhost:8080/query \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { ingestHasMetadata(subject: {package: {packageInput: {type: \"guac\", namespace: \"pkg/myorg\", name: \"myrepo\", version: \"1.0.0\"}}}, pkgMatchType: {pkg: SPECIFIC_VERSION}, hasMetadata: {key: \"nitrogate:pr\", value: \"123\", justification: \"Quality gate ran on PR #123\", timestamp: \"2026-03-03T07:35:00Z\", origin: \"nitrogate\", collector: \"nitrogate-v1\", documentRef: \"nitrogate-pr123-meta\"}) }"
  }'
# Expected: {"data":{"ingestHasMetadata":"11"}}

# Mutation 3: Critical findings count
curl -s http://localhost:8080/query \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { ingestHasMetadata(subject: {package: {packageInput: {type: \"guac\", namespace: \"pkg/myorg\", name: \"myrepo\", version: \"1.0.0\"}}}, pkgMatchType: {pkg: SPECIFIC_VERSION}, hasMetadata: {key: \"nitrogate:critical-findings\", value: \"2\", justification: \"compromised-package:event-stream, aws-key:config.ts\", timestamp: \"2026-03-03T07:35:00Z\", origin: \"nitrogate\", collector: \"nitrogate-v1\", documentRef: \"nitrogate-pr123-findings\"}) }"
  }'
# Expected: {"data":{"ingestHasMetadata":"12"}}
```

### 3.5 Run demo queries

**Query 1 — "Which repos/packages failed the quality gate?"**

```bash
curl -s http://localhost:8080/query \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ HasMetadata(hasMetadataSpec: {key: \"nitrogate:decision\", value: \"FAIL\"}) { id key value justification timestamp origin subject { __typename ... on Package { type namespaces { namespace names { name versions { version } } } } } } }"
  }' | python3 -m json.tool
```

Expected: returns `myorg/myrepo` with FAIL, justification showing 3 findings.

**Query 2 — "Show all NitroGate metadata for a repo"**

```bash
curl -s http://localhost:8080/query \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ HasMetadata(hasMetadataSpec: {origin: \"nitrogate\"}) { id key value justification timestamp subject { __typename ... on Package { type namespaces { namespace names { name versions { version } } } } } } }"
  }' | python3 -m json.tool
```

Expected: returns all 3 metadata entries (decision, PR number, critical findings).

**Query 3 — "Packages with SBOMs"**

```bash
curl -s http://localhost:8080/query \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ HasSBOM(hasSBOMSpec: {}) { id uri subject { __typename ... on Package { type namespaces { namespace names { name } } } } } }"
  }' | python3 -m json.tool
```

Expected: returns `myorg/myrepo` SBOM with SPDX document URI.

**You can also open http://localhost:8080 in a browser** — this is the GUAC GraphQL Playground where you can type queries interactively.

### 3.6 Stop / Restart GUAC

```bash
# Stop
docker compose -f /Users/rahulxf/aflockGate/deploy/guac-demo-compose.yaml -p guac down

# Restart (data is in-memory, lost on restart — re-run 3.3 and 3.4 to repopulate)
docker compose -f /Users/rahulxf/aflockGate/deploy/guac-demo-compose.yaml -p guac up -d
```

---

## 4. Quality Gates

### 4.1 Install dependencies

```bash
cd /Users/rahulxf/quality-gates

# Refresh private registry tokens (if expired)
./ar-login.sh

# Install
yarn install
```

### 4.2 Create test data (one-time setup)

```bash
cd /Users/rahulxf/quality-gates
mkdir -p workdir/results workdir/test-repo/.github/workflows

# Test package.json with known-bad deps
cat > workdir/test-repo/package.json << 'EOF'
{
  "name": "test-app",
  "dependencies": {
    "event-stream": "^3.3.6",
    "expresss": "^1.0.0",
    "lodash": "^4.17.21"
  }
}
EOF

# Test file with leaked secrets
cat > workdir/test-repo/config.ts << 'EOF'
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
const stripe_key = "STRIPE_SECRET_KEY_EXAMPLE_VALUE_HERE"
const password = "SuperSecretJWT12345678901234567890abcdef"
const safe_variable = "hello world"
EOF

# Test workflow with 4 security issues
cat > workdir/test-repo/.github/workflows/ci.yml << 'EOF'
name: CI
on: pull_request_target
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: some-random-org/action@main
      - run: echo "PR title is ${{ github.event.pull_request.title }}"
EOF

# Create file lists (one file path per line, relative to TARGET_REPO_PATH)
echo "package.json" > workdir/test-files-npm.txt
echo "config.ts" > workdir/test-files-secret.txt
echo ".github/workflows/ci.yml" > workdir/test-files-workflow.txt
```

### 4.3 Test each gate

**NPM Supply Chain Check:**

```bash
cd /Users/rahulxf/quality-gates

TARGET_REPO_PATH=/Users/rahulxf/quality-gates/workdir/test-repo \
TEAM_FILES=/Users/rahulxf/quality-gates/workdir/test-files-npm.txt \
WORKDIR=/Users/rahulxf/quality-gates/workdir \
TEAM=test \
npx ts-node scripts/npm_supply_chain_check.ts

cat workdir/results/test-npm_supply_chain_check.json | python3 -m json.tool
```

Expected result — **FAILURE, 2 errors**:

```json
{
  "status": "failure",
  "script": "npm_supply_chain_check",
  "team": "test",
  "details": {
    "errorCount": 2,
    "warningCount": 0,
    "issues": [
      {
        "message": "COMPROMISED: event-stream@3.3.6 — Hijacked via flatmap-stream — cryptocurrency wallet theft (2018)",
        "severity": "error",
        "ruleId": "compromised-package"
      },
      {
        "message": "TYPOSQUAT: 'expresss' is suspiciously similar to 'express' — verify you installed the correct package",
        "severity": "error",
        "ruleId": "typosquat-suspect"
      }
    ]
  }
}
```

**Secret Scanning Check:**

```bash
TARGET_REPO_PATH=/Users/rahulxf/quality-gates/workdir/test-repo \
TEAM_FILES=/Users/rahulxf/quality-gates/workdir/test-files-secret.txt \
WORKDIR=/Users/rahulxf/quality-gates/workdir \
TEAM=test \
npx ts-node scripts/secret_scanning_check.ts

cat workdir/results/test-secret_scanning_check.json | python3 -m json.tool
```

Expected result — **FAILURE, 2 errors**:

```json
{
  "status": "failure",
  "details": {
    "errorCount": 2,
    "issues": [
      { "message": "AWS: AWS Access Key ID detected at line 1", "ruleId": "aws-access-key" },
      { "message": "Stripe: Stripe Live Secret Key detected at line 2", "ruleId": "stripe-live" }
    ]
  }
}
```

**Workflow Security Check:**

```bash
TARGET_REPO_PATH=/Users/rahulxf/quality-gates/workdir/test-repo \
TEAM_FILES=/Users/rahulxf/quality-gates/workdir/test-files-workflow.txt \
WORKDIR=/Users/rahulxf/quality-gates/workdir \
TEAM=test \
npx ts-node scripts/workflow_security_check.ts

cat workdir/results/test-workflow_security_check.json | python3 -m json.tool
```

Expected result — **FAILURE, 2 errors + 2 warnings**:

```json
{
  "status": "failure",
  "details": {
    "errorCount": 2,
    "warningCount": 2,
    "issues": [
      { "message": "PWN REQUEST: Workflow uses 'pull_request_target' trigger with 'actions/checkout' that checks out PR HEAD...", "severity": "error", "ruleId": "pwn-request" },
      { "message": "SCRIPT INJECTION: Job 'build' step 3 uses untrusted context '${{ github.event.pull_request.title }}'...", "severity": "error", "ruleId": "script-injection" },
      { "message": "EXCESSIVE PERMISSIONS: Workflow-level 'permissions: write-all'...", "severity": "warning", "ruleId": "excessive-permissions" },
      { "message": "UNPINNED ACTION: 'some-random-org/action@main'...", "severity": "warning", "ruleId": "unpinned-action" }
    ]
  }
}
```

---

## 5. Testing on Your Personal GitHub Repo

You can run every gate against any repo you have locally. No GitHub token needed — the gates read files from disk.

### 5.1 Scan any local repo for NPM supply chain issues

```bash
cd /Users/rahulxf/quality-gates

# Replace with your repo path
MY_REPO=/Users/rahulxf/my-personal-repo

# Find all package.json files (skip node_modules)
find "$MY_REPO" -name "package.json" -not -path "*/node_modules/*" | \
  sed "s|$MY_REPO/||" > workdir/my-repo-pkg-files.txt

# Run NPM supply chain check
TARGET_REPO_PATH="$MY_REPO" \
TEAM_FILES=/Users/rahulxf/quality-gates/workdir/my-repo-pkg-files.txt \
WORKDIR=/Users/rahulxf/quality-gates/workdir \
TEAM=personal \
npx ts-node scripts/npm_supply_chain_check.ts

# View results
cat workdir/results/personal-npm_supply_chain_check.json | python3 -m json.tool
```

### 5.2 Scan any local repo for leaked secrets

```bash
MY_REPO=/Users/rahulxf/my-personal-repo

# Find source files (skip binaries and node_modules)
find "$MY_REPO" \( -name "*.ts" -o -name "*.js" -o -name "*.tsx" -o -name "*.jsx" \
  -o -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name "*.env" \) \
  -not -path "*/node_modules/*" -not -path "*/dist/*" -not -path "*/.git/*" | \
  sed "s|$MY_REPO/||" > workdir/my-repo-src-files.txt

# Run secret scanning
TARGET_REPO_PATH="$MY_REPO" \
TEAM_FILES=/Users/rahulxf/quality-gates/workdir/my-repo-src-files.txt \
WORKDIR=/Users/rahulxf/quality-gates/workdir \
TEAM=personal \
npx ts-node scripts/secret_scanning_check.ts

cat workdir/results/personal-secret_scanning_check.json | python3 -m json.tool
```

### 5.3 Scan any local repo for workflow security issues

```bash
MY_REPO=/Users/rahulxf/my-personal-repo

# Find GitHub Actions workflow files
find "$MY_REPO/.github/workflows" -name "*.yml" -o -name "*.yaml" 2>/dev/null | \
  sed "s|$MY_REPO/||" > workdir/my-repo-workflow-files.txt

# Run workflow security check
TARGET_REPO_PATH="$MY_REPO" \
TEAM_FILES=/Users/rahulxf/quality-gates/workdir/my-repo-workflow-files.txt \
WORKDIR=/Users/rahulxf/quality-gates/workdir \
TEAM=personal \
npx ts-node scripts/workflow_security_check.ts

cat workdir/results/personal-workflow_security_check.json | python3 -m json.tool
```

### 5.4 Run all 3 gates in one shot (convenience script)

```bash
#!/bin/bash
# Save as: /Users/rahulxf/quality-gates/scan-repo.sh

MY_REPO="${1:-.}"
cd /Users/rahulxf/quality-gates
mkdir -p workdir/results

echo "Scanning: $MY_REPO"
echo "================================"

# NPM
find "$MY_REPO" -name "package.json" -not -path "*/node_modules/*" | \
  sed "s|$MY_REPO/||" > workdir/auto-pkg.txt
if [ -s workdir/auto-pkg.txt ]; then
  echo ""
  echo "--- NPM Supply Chain ---"
  TARGET_REPO_PATH="$MY_REPO" TEAM_FILES=workdir/auto-pkg.txt \
    WORKDIR=workdir TEAM=scan npx ts-node scripts/npm_supply_chain_check.ts 2>/dev/null
  python3 -c "import json; d=json.load(open('workdir/results/scan-npm_supply_chain_check.json')); print(f'Status: {d[\"status\"]} | Errors: {d[\"details\"][\"errorCount\"]} | Warnings: {d[\"details\"][\"warningCount\"]}')"
fi

# Secrets
find "$MY_REPO" \( -name "*.ts" -o -name "*.js" -o -name "*.json" -o -name "*.yaml" \
  -o -name "*.yml" -o -name "*.env" \) \
  -not -path "*/node_modules/*" -not -path "*/dist/*" -not -path "*/.git/*" | \
  sed "s|$MY_REPO/||" > workdir/auto-src.txt
if [ -s workdir/auto-src.txt ]; then
  echo ""
  echo "--- Secret Scanning ---"
  TARGET_REPO_PATH="$MY_REPO" TEAM_FILES=workdir/auto-src.txt \
    WORKDIR=workdir TEAM=scan npx ts-node scripts/secret_scanning_check.ts 2>/dev/null
  python3 -c "import json; d=json.load(open('workdir/results/scan-secret_scanning_check.json')); print(f'Status: {d[\"status\"]} | Errors: {d[\"details\"][\"errorCount\"]} | Warnings: {d[\"details\"][\"warningCount\"]}')"
fi

# Workflows
if [ -d "$MY_REPO/.github/workflows" ]; then
  find "$MY_REPO/.github/workflows" \( -name "*.yml" -o -name "*.yaml" \) | \
    sed "s|$MY_REPO/||" > workdir/auto-wf.txt
  if [ -s workdir/auto-wf.txt ]; then
    echo ""
    echo "--- Workflow Security ---"
    TARGET_REPO_PATH="$MY_REPO" TEAM_FILES=workdir/auto-wf.txt \
      WORKDIR=workdir TEAM=scan npx ts-node scripts/workflow_security_check.ts 2>/dev/null
    python3 -c "import json; d=json.load(open('workdir/results/scan-workflow_security_check.json')); print(f'Status: {d[\"status\"]} | Errors: {d[\"details\"][\"errorCount\"]} | Warnings: {d[\"details\"][\"warningCount\"]}')"
  fi
fi

echo ""
echo "================================"
echo "Full JSON results in: workdir/results/"
```

Usage:

```bash
chmod +x scan-repo.sh
./scan-repo.sh /Users/rahulxf/my-personal-repo
```

---

## 6. End-to-End Demo Flow

This is the exact sequence to demo everything working together:

```bash
# 1. Show Go tests passing
cd /Users/rahulxf/aflockGate
go test ./internal/... -count=1
# Shows: attest OK, gate OK, scanner OK (30+ tests)

# 2. Build the binary
go build -o bin/nitrogate ./cmd/nitrogate/
ls -lh bin/nitrogate

# 3. Start GUAC
cd deploy
docker compose -f guac-demo-compose.yaml -p guac up -d
# Wait 10 seconds for health checks

# 4. Generate and ingest test data
cd /Users/rahulxf/aflockGate
go run test-guac/generate_attestation.go
docker run --rm --network guac_default \
  -v "$(pwd)/test-guac:/data" \
  ghcr.io/guacsec/guac:v1.0.1 \
  /opt/guac/guacone collect files /data/ \
  --gql-addr http://graphql:8080/query \
  --csub-addr collectsub:2782

# 5. Certify gate results in GUAC
curl -s http://localhost:8080/query -H "Content-Type: application/json" -d '{
  "query": "mutation { ingestHasMetadata(subject: {package: {packageInput: {type: \"guac\", namespace: \"pkg/myorg\", name: \"myrepo\", version: \"1.0.0\"}}}, pkgMatchType: {pkg: SPECIFIC_VERSION}, hasMetadata: {key: \"nitrogate:decision\", value: \"FAIL\", justification: \"3 findings — 2 critical (compromised event-stream, AWS key), 1 medium (lodash cooldown)\", timestamp: \"2026-03-03T07:35:00Z\", origin: \"nitrogate\", collector: \"nitrogate-v1\", documentRef: \"nitrogate-pr123\"}) }"
}'

# 6. Query GUAC — "Which repos failed?"
curl -s http://localhost:8080/query -H "Content-Type: application/json" -d '{
  "query": "{ HasMetadata(hasMetadataSpec: {key: \"nitrogate:decision\", value: \"FAIL\"}) { id key value justification origin subject { __typename ... on Package { type namespaces { namespace names { name versions { version } } } } } } }"
}' | python3 -m json.tool

# 7. Run quality gates against test data
cd /Users/rahulxf/quality-gates
TARGET_REPO_PATH=workdir/test-repo TEAM_FILES=workdir/test-files-npm.txt \
  WORKDIR=workdir TEAM=test npx ts-node scripts/npm_supply_chain_check.ts
cat workdir/results/test-npm_supply_chain_check.json | python3 -m json.tool

# 8. Open GUAC playground in browser
open http://localhost:8080
```

---

## 7. Known Issues & Expected Errors

### GUAC ingestion: "1 of 4 were successful"

**Expected.** Only `sbom.json` ingests. The failures:
- `attestation.json` — "failed to verify identity: failed to find key from key providers" — GUAC validates DSSE signatures against keystore. Our test signature uses a dummy key. In production, Sigstore/Fulcio would provide verifiable signatures.
- `envelope.json` — "no document processor registered for type: UNKNOWN" — leftover file from earlier run, safe to ignore.
- `generate_attestation.go` — "UNKNOWN format" — it's Go source code, not a document.

**The SBOM ingests fine, and we use GraphQL mutations (not file ingestion) for gate results — so everything works.**

### GUAC compose: "version is obsolete"

**Expected.** Docker Compose v2 ignores the `version` field. No impact.

### Quality gates: "PLATFORM_CORE_OBSERVABILITY" messages

**Expected.** The quality-gates framework initializes OpenTelemetry on import. These are informational logs, not errors.

### Quality gates: "punycode module deprecated"

**Expected.** Node.js deprecation warning for the `punycode` built-in. No impact.

### Devtool frontend: "Redirect URI Error"

**Expected.** The Authentik SSO is configured with redirect URIs for the deployed environment (e.g. `https://devtools.leadconnectorhq.com`), not `localhost:8082`. Would need Authentik admin access to add localhost as an allowed redirect. **Not needed for the hackathon demo — the quality gate results are shown via JSON output and GUAC queries instead.**

---

## 8. Files Changed (Nothing Pushed)

### `/Users/rahulxf/aflockGate/` (your project)

| File | Action | Description |
|---|---|---|
| `internal/scanner/npm_supply_chain.go` | Created | NPM supply chain scanner (374 lines) |
| `internal/scanner/npm_supply_chain_test.go` | Created | 8 unit tests |
| `internal/guac/client.go` | Updated | GraphQL mutations instead of guacone CLI |
| `cmd/nitrogate/main.go` | Updated | Wired NPM scanner + updated CertifyGate call |
| `deploy/guac-demo-compose.yaml` | Downloaded | Official GUAC v1.0.1 compose file |
| `test-guac/generate_attestation.go` | Created | Test data generator |
| `test-guac/attestation.json` | Generated | DSSE envelope (test) |
| `test-guac/sbom.json` | Generated | SPDX SBOM (test) |
| `docs/testing-guide.md` | Created | This document |

### `/Users/rahulxf/quality-gates/` (company repo — local only)

| File | Action | Description |
|---|---|---|
| `scripts/npm_supply_chain_check.ts` | Created | NPM cooldown + compromised + typosquat gate |
| `scripts/workflow_security_check.ts` | Created | GitHub Actions security gate |
| `scripts/secret_scanning_check.ts` | Created | Enhanced secret scanning with entropy |
| `runners/gateRegistry.ts` | Modified | Added 3 imports + registrations |
| `config/config.ts` | Modified | Added 3 gate configs |
| `workdir/` | Created | Local test data (gitignored by convention) |

### `/Users/rahulxf/devtool/` (company dashboard — no changes)

Only `yarn install --ignore-engines` was run. No source files modified.
