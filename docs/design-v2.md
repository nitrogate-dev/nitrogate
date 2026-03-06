# NitroGate v2 — Design Document (Go + GUAC)

## Problem Statement

Modern software teams merge hundreds of pull requests per week. Each merge is a supply chain decision: are the dependencies safe? Are there leaked secrets? Is the CI workflow itself secure? Are licenses compliant?

Today, teams stitch together 5-10 separate tools (see: Chainguard's PR with 62 checks from Orca, Semgrep, StepSecurity, Enforce). Each tool has its own config, its own output format, its own alert fatigue. None of them talk to each other. And critically — **no one can answer cross-cutting questions**: "Which of our 200 repos are affected by this CVE?" or "Show me every PR merged last month without a passing quality gate."

**NitroGate v2** solves three problems:

1. **Unified quality gate** — One tool, one config (`.nitrogate.json`), one PR comment with secrets + vulnerabilities + workflow security + license compliance + AI code review. No more 10 separate checks.

2. **Cryptographic attestation** — Every gate decision produces a signed [in-toto v1](https://github.com/in-toto/attestation) attestation. You can prove what was checked, what was found, and what decision was made — offline, after the fact, by any third party.

3. **Organizational intelligence via GUAC** — Attestations feed into [GUAC](https://github.com/guacsec/guac) (Graph for Understanding Artifact Composition), enabling fleet-wide queries: "Which repos have CVE-X?", "Which PRs bypassed the gate?", "Trace this image back to its source PR."

## Proposed Solution

A Go-based CLI tool that runs as a GitHub Action. It executes a deterministic pipeline on every PR:

```
PR event
  → Load policy (.nitrogate.json)
  → Verify policy integrity (optional Sigstore check)
  → Run scanners in parallel:
      ├── Secret Scanner (regex + entropy on diff)
      ├── Dependency Scanner (lockfile parse + OSV.dev API)
      ├── NPM Supply Chain (cooldown + compromised + typosquatting)
      ├── Workflow Security (script injection + pwn request + pin check)
      ├── License Checker (registry metadata)
      └── LLM Review (OpenAI / Anthropic / mock)
  → Aggregate findings → apply severity thresholds → gate decision
  → Build in-toto attestation → sign (Ed25519 / Sigstore)
  → Post PR comment with all findings
  → Push attestation to GUAC
  → Upload artifacts
```

## Tech Stack & Architecture

### Stack

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | Go 1.22+ | Native ecosystem for supply chain tools (GUAC, cosign, in-toto, Witness are all Go) |
| GitHub API | `go-github/v60` | Mature, well-maintained GitHub REST API client |
| Attestation | in-toto v1 + DSSE | Industry standard; GUAC, Witness, SLSA all use it |
| Signing | Ed25519 (Go stdlib `crypto/ed25519`) | Fast, no dependencies; Sigstore as Phase 2 |
| Vuln Data | OSV.dev REST API | Free, open, covers NVD/GitHub Advisory/PyPI/RubyGems/Go |
| Policy | JSON + Go `encoding/json` | Simple, no external deps |
| Graph DB | GUAC (docker-compose) | Aggregates all attestations into queryable graph |
| Testing | Go `testing` + `testify` | Standard Go testing |
| CI | GitHub Actions (Docker container action) | Runs where the code lives |

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    NitroGate CLI / GitHub Action                 │
│                                                                  │
│  cmd/nitrogate/main.go                                         │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Pipeline Orchestrator                                       │ │
│  │                                                             │ │
│  │  1. Load Policy ──────────────── internal/policy/           │ │
│  │  2. Get PR Context ───────────── internal/github/           │ │
│  │  3. Run Scanners (parallel) ──── internal/scanner/          │ │
│  │     ├── secrets.go                                          │ │
│  │     ├── deps.go          ──── OSV.dev API                   │ │
│  │     ├── npm.go           ──── npm Registry API              │ │
│  │     ├── workflow.go                                         │ │
│  │     ├── license.go       ──── Registry APIs                 │ │
│  │     └── llm.go           ──── OpenAI / Anthropic API        │ │
│  │  4. Gate Decision ────────────── internal/gate/              │ │
│  │  5. Build Attestation ────────── internal/attest/            │ │
│  │  6. Post PR Comment ─────────── internal/output/             │ │
│  │  7. Push to GUAC ────────────── internal/guac/               │ │
│  └────────────────────────────────────────────────────────────┘ │
└───────────────────────────┬─────────────────────────────────────┘
                            │ in-toto attestation (signed)
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  GUAC (docker-compose)                                           │
│                                                                  │
│  guacone collect files ./attestations/                           │
│  ├── Ingestor: parses in-toto statement                         │
│  ├── Assembler: builds graph nodes                              │
│  └── GraphQL API (port 8080):                                   │
│      ├── "Which packages have CVE-X?"                           │
│      ├── "certifyBad: PRs that failed the gate"                 │
│      ├── "certifyGood: PRs that passed the gate"                │
│      └── "Trace: image → build → PR → commit"                  │
└─────────────────────────────────────────────────────────────────┘
```

### Directory Structure

```
nitrogate/
├── cmd/
│   └── nitrogate/
│       └── main.go                 # CLI entry point + pipeline orchestration
│
├── internal/
│   ├── github/
│   │   └── client.go               # GitHub API: PR context, diff, files, comment
│   │
│   ├── policy/
│   │   └── policy.go               # Load .nitrogate.json, evaluate rules
│   │
│   ├── scanner/
│   │   ├── types.go                # Finding, Severity, ScanResult types
│   │   ├── secrets.go              # Secret detection (regex + entropy)
│   │   ├── secrets_patterns.go     # Pattern definitions
│   │   ├── deps.go                 # Dependency scanner + OSV.dev client
│   │   ├── npm.go                  # NPM supply chain (cooldown, compromised)
│   │   ├── workflow.go             # Workflow security (injection, pwn, pins)
│   │   ├── license.go              # License compliance checker
│   │   └── llm.go                  # LLM code review (OpenAI/Anthropic/mock)
│   │
│   ├── gate/
│   │   └── gate.go                 # Aggregate findings → PASS/FAIL decision
│   │
│   ├── attest/
│   │   ├── intoto.go               # in-toto v1 Statement builder
│   │   ├── dsse.go                 # DSSE envelope wrapper
│   │   ├── sign.go                 # Ed25519 signing
│   │   └── verify.go               # Signature verification
│   │
│   ├── guac/
│   │   └── client.go               # Push attestations to GUAC, query API
│   │
│   └── output/
│       └── comment.go              # PR comment formatting + artifact writing
│
├── deploy/
│   └── docker-compose.guac.yml     # GUAC setup for demo/production
│
├── Dockerfile                      # Docker container action
├── action.yml                      # GitHub Action definition
├── go.mod
├── go.sum
├── .nitrogate.json                    # Example policy
│
├── docs/
│   ├── design-v2.md                # This document
│   ├── design.md                   # Original v1 design (TypeScript)
│   ├── roadmap.md                  # Full roadmap
│   └── complete-plan.md            # Complete check matrix
│
└── tests/                          # Test data and fixtures
    ├── fixtures/
    │   ├── diff-with-secrets.patch
    │   ├── package-lock-vuln.json
    │   ├── workflow-injectable.yml
    │   └── policy-strict.json
    └── integration/
        └── pipeline_test.go
```

### Data Flow

```
                    ┌───────────┐
                    │ PR Event  │
                    └─────┬─────┘
                          │
                    ┌─────▼─────┐
                    │  Policy   │ ← .nitrogate.json
                    │  Load     │
                    └─────┬─────┘
                          │
              ┌───────────┼───────────┬──────────┬──────────┐
              ▼           ▼           ▼          ▼          ▼
        ┌──────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
        │ Secrets  │ │ Deps   │ │ NPM    │ │Workflow│ │License │
        │ Scanner  │ │+OSV    │ │Supply  │ │Security│ │Checker │
        └────┬─────┘ └───┬────┘ └───┬────┘ └───┬────┘ └───┬────┘
             │            │          │          │          │
             └────────────┴──────────┴──────────┴──────────┘
                                     │
                              Finding[]
                                     │
                              ┌──────▼──────┐
                              │    Gate     │
                              │  Decision  │
                              │ PASS/FAIL  │
                              └──────┬──────┘
                                     │
                    ┌────────────────┬┴────────────────┐
                    ▼                ▼                  ▼
             ┌────────────┐  ┌────────────┐    ┌────────────┐
             │  in-toto   │  │ PR Comment │    │   GUAC     │
             │ Attestation│  │ (GitHub)   │    │  Ingest    │
             │ (signed)   │  └────────────┘    └────────────┘
             └────────────┘
```

## Scanner Details

### Secret Scanner

Scans `+` lines from the PR diff for credential patterns.

| Pattern | Regex | Severity |
|---------|-------|----------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | critical |
| AWS Secret Key | `(?i)aws_secret_access_key\s*=\s*\S{40}` | critical |
| GitHub PAT | `gh[pousr]_[A-Za-z0-9_]{36,}` | critical |
| GitHub Fine-grained | `github_pat_[A-Za-z0-9_]{82}` | critical |
| Private Key PEM | `-----BEGIN (RSA\|EC\|DSA\|OPENSSH) PRIVATE KEY-----` | critical |
| Google API Key | `AIza[0-9A-Za-z_-]{35}` | critical |
| Slack Token | `xox[bpors]-[A-Za-z0-9-]{10,}` | high |
| Stripe Key | `sk_live_[A-Za-z0-9]{24,}` | critical |
| JWT | `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` | high |
| DB Connection String | `(postgres\|mysql\|mongodb\|redis)://[^\s]{10,}` | high |
| Generic API Key | `(?i)api[_-]?(key\|secret\|token)\s*[:=]\s*['"][^\s'"]{16,}` | medium |
| High Entropy | Shannon entropy > 4.5 in assignment | low |

**Design decisions**:
- Only scan `+` lines (new/modified content)
- Redact matches — never expose secrets in attestations or PR comments
- Support `allowFiles` patterns for test fixtures
- Support custom patterns in policy

### Dependency Scanner

Parses lockfiles from the PR, queries [OSV.dev](https://osv.dev/) for vulnerabilities.

**Supported lockfiles**: `package-lock.json`, `yarn.lock`, `go.sum`, `requirements.txt`, `poetry.lock`, `Cargo.lock`, `Gemfile.lock`, `pom.xml`.

**Vulnerability scoring**:
```
risk = CVSS × EPSS × KEV_multiplier × depth_factor
KEV_multiplier = 2.0 if in CISA KEV, else 1.0
depth_factor = 1.0 / (transitive_depth + 1)
```

### NPM Supply Chain Checks

Inspired by StepSecurity:
- **Compromised packages**: Cross-reference against known-bad package+version list
- **Package cooldown**: Flag packages published within N days (default: 7)
- **Typosquatting**: Levenshtein distance against top-1000 npm packages
- **Install scripts**: Flag packages with `preinstall`/`postinstall` hooks

### Workflow Security Scanner

Inspired by StepSecurity:
- **Script injection**: Detect `${{ github.event.* }}` in `run:` blocks
- **Pwn request**: Detect `pull_request_target` + checkout of PR head
- **Unpinned actions**: Flag `uses: action@tag` (should be `@sha`)
- **Excessive permissions**: Flag `write-all` or overly broad `permissions:`
- **Secrets in logs**: Detect `echo ${{ secrets.* }}`

### License Checker

For newly added dependencies, resolve license via registry APIs:
- npm: `registry.npmjs.org/{pkg}/{ver}` → `.license`
- PyPI: `pypi.org/pypi/{pkg}/{ver}/json` → `.info.license`

Categories: permissive (allow), weak copyleft (warn), strong copyleft (deny), AGPL (deny), unknown (warn).

## GUAC Integration

### How It Works

1. NitroGate produces in-toto attestations for each PR scan
2. Attestations are written to `./nitrogate-attestations/`
3. `guacone collect files ./nitrogate-attestations/` ingests into GUAC
4. For passing PRs: `guacone certify package --good "nitrogate: passed" "pkg:github/org/repo@sha"`
5. For failing PRs: `guacone certify package --bad "nitrogate: failed - 2 critical vulns" "pkg:github/org/repo@sha"`
6. GUAC GraphQL queries provide organizational intelligence

### Demo Queries

**"Which packages/repos are affected by CVE-2021-23337?"**
```graphql
{
  vulnerabilities(vulnerabilityID: "CVE-2021-23337") {
    type
    vulnerabilityIDs {
      vulnerabilityID
    }
  }
}
```

**"Show me all PRs that failed the quality gate"**
```graphql
{
  CertifyBad {
    subject {
      ... on Package {
        namespaces {
          namespace
          names { name }
        }
      }
    }
    justification
    origin
  }
}
```

**"Show me packages certified as safe by NitroGate"**
```graphql
{
  CertifyGood(certifyGoodSpec: { origin: "nitrogate" }) {
    subject {
      ... on Package {
        namespaces {
          namespace
          names { name }
        }
      }
    }
    justification
  }
}
```

### Setup

```bash
# Start GUAC (demo mode, in-memory)
docker compose -f deploy/docker-compose.guac.yml up -d

# Ingest attestations
guacone collect files ./nitrogate-attestations/

# Certify gate decisions
guacone certify package --good "nitrogate: passed all checks" "pkg:github/myorg/myrepo@abc123"

# Query
# Open http://localhost:8080 for GraphQL playground
```

## Success Metrics

| Metric | Target | How Measured |
|--------|--------|--------------|
| Scanners functional | All 5 scanners detect planted issues | Integration test with fixture data |
| Secret detection | Catches AWS keys, GitHub PATs, private keys, JWTs | Unit tests with known patterns |
| Vuln detection | Catches known CVEs via OSV.dev | Unit test with known-vulnerable lockfile |
| Workflow security | Catches script injection + pwn request | Unit test with bad workflow YAML |
| GUAC ingestion | Attestations appear in GUAC graph | Manual verification via GraphQL |
| GUAC queries | "affected repos" and "failed gate" queries return data | Manual verification |
| Gate accuracy | PASS for clean PRs, FAIL for PRs with critical findings | Integration test |
| Attestation integrity | Sign → verify round-trip works; tamper → fails | Unit tests |
| Time to scan | < 30s for a typical PR | CI timing |
| Test coverage | 30+ passing tests | `go test ./...` |

## Test Strategy

### Unit Tests

| Suite | Tests |
|-------|-------|
| `scanner/secrets_test.go` | Pattern matching for each secret type, entropy calculation, redaction, allowlist |
| `scanner/deps_test.go` | Lockfile parsing (npm, go, python), OSV response handling, risk scoring |
| `scanner/npm_test.go` | Cooldown calculation, compromised package lookup, typosquatting distance |
| `scanner/workflow_test.go` | Script injection detection, pwn request detection, pin verification |
| `scanner/license_test.go` | License classification, policy evaluation |
| `attest/intoto_test.go` | Statement construction, predicate serialization |
| `attest/sign_test.go` | Ed25519 sign+verify, tamper detection |
| `gate/gate_test.go` | Threshold evaluation, severity aggregation, mode handling |
| `policy/policy_test.go` | Policy loading, default fallback, schema validation |

### Integration Tests

| Test | Scope |
|------|-------|
| Full pipeline | Mock GitHub + fixture diff → all scanners → gate → attestation → verify |
| GUAC round-trip | Produce attestation → ingest into GUAC → query and verify presence |

## Production Plan

### Phase 1: Hackathon (Current)
- All 5 scanners working
- Ed25519 attestation signing
- GUAC integration (demo mode)
- GitHub Action (Docker container)
- Unit + integration tests

### Phase 2: Production Hardening (Post-hackathon, 2-4 weeks)
- Sigstore keyless signing (Fulcio + Rekor) — no key management
- cosign image signature verification in Dockerfile scanner
- OCI registry storage for attestations
- Config integrity verification (nono-style policy signing)
- Rate limiting and retry for external APIs (OSV, npm registry)

### Phase 3: Enterprise (1-3 months)
- GitHub App mode (webhooks, approval attestation)
- Witness-style CI step attestation (`nitrogate/witness-step`)
- Multi-repo policy inheritance
- GUAC production deployment (PostgreSQL backend)
- SLSA level assessment
- Harden-Runner integration for CI network monitoring
- Semgrep integration for SAST

## Risks & Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| OSV.dev API rate limiting | Dep scanner fails | Medium | Cache responses, batch queries, retry with backoff |
| npm registry rate limiting | NPM checks fail | Medium | Cache responses, retry with backoff |
| GUAC docker-compose fails during demo | Can't show org queries | Low | Pre-record backup, have local GUAC pre-populated |
| Large diff overwhelms scanners | Slow scan, timeout | Medium | Diff truncation (existing), parallel scanner execution |
| False positives in secret scanner | Alert fatigue | Medium | Tunable entropy threshold, allowlist patterns |
| Go binary too large for Action | Slow startup | Low | Use scratch/distroless base image, strip binary |
| Fork PRs lack secrets | Can't sign attestation | High (by design) | Graceful degradation: skip signing, still scan and report |

## Security Considerations

- No secrets in code or logs — all keys via environment variables
- Secret scanner redacts findings — never exposes the actual credential
- Attestation private key is ephemeral (Phase 2: Sigstore OIDC)
- GUAC demo runs locally — no production data exposed
- OSV.dev queries contain only package names + versions (no proprietary data)
- PR comment contains finding summaries, not raw diff content
