# AflockGate — Supply Chain Quality Gate Roadmap

## Vision

AflockGate evolves from an AI PR reviewer into a **unified supply chain quality gate** — a single platform that answers: "Is this change safe to merge?" and "Is this artifact safe to deploy?" with cryptographic proof at every step.

The LLM review is one signal among many. The real value is the **gate** itself: a composable set of security checks, each producing a signed attestation, feeding into a graph database for organizational intelligence.

## Landscape: Where Each Tool Fits

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Developer pushes code                         │
└─────────────────────────┬───────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PR-TIME CHECKS (AflockGate Core)                                    │
│                                                                      │
│  ┌─────────────┐ ┌──────────────┐ ┌────────────┐ ┌──────────────┐  │
│  │ Secret      │ │ Dependency   │ │ License    │ │ Policy       │  │
│  │ Scanner     │ │ Scanner      │ │ Checker    │ │ Engine       │  │
│  │             │ │ (OSV.dev)    │ │            │ │ (.aflock)    │  │
│  └──────┬──────┘ └──────┬───────┘ └─────┬──────┘ └──────┬───────┘  │
│         │               │               │               │           │
│  ┌──────▼───────────────▼───────────────▼───────────────▼────────┐  │
│  │              Attestation Layer                                 │  │
│  │  Format:  in-toto v1 Statement + DSSE Envelope                │  │
│  │  Signing: Sigstore Fulcio (keyless) | Ed25519 (fallback)     │  │
│  │  Log:     Rekor transparency log                              │  │
│  │  Verify:  cosign verify-attestation                           │  │
│  └──────────────────────┬────────────────────────────────────────┘  │
│                         │                                            │
│  ┌──────────────────────▼────────────────────────────────────────┐  │
│  │  Config Integrity (nono-inspired)                              │  │
│  │  .aflock.json is itself signed — tampered policy = gate fail  │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────┬───────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│  BUILD-TIME ATTESTATION (Witness-style)                              │
│                                                                      │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │ aflockgate/      │  │ aflockgate/      │  │ aflockgate/      │  │
│  │ witness-step     │  │ witness-step     │  │ witness-step     │  │
│  │ step: build      │  │ step: test       │  │ step: publish    │  │
│  │ cmd: npm build   │  │ cmd: npm test    │  │ cmd: docker push │  │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘  │
│           │                     │                      │            │
│  ┌────────▼─────────────────────▼──────────────────────▼─────────┐  │
│  │  cosign sign (keyless) — sign container images/artifacts      │  │
│  │  cosign verify — verify base images before build              │  │
│  └──────────────────────────────┬────────────────────────────────┘  │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│  DEPLOY-TIME GATE (Pipeline Verification)                            │
│                                                                      │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  aflockgate verify-pipeline                                    │  │
│  │                                                                │  │
│  │  ✓ PR review attestation exists and signature valid            │  │
│  │  ✓ No critical/high vulnerabilities in dependencies            │  │
│  │  ✓ No secrets detected in diff                                 │  │
│  │  ✓ License compliance passed                                   │  │
│  │  ✓ Build step attestation exists (Witness-style)               │  │
│  │  ✓ Test step attestation exists with exit code 0               │  │
│  │  ✓ Container image signed (cosign verify)                      │  │
│  │  ✓ Base images verified (cosign verify)                        │  │
│  │  ✓ Policy file integrity verified (nono-style)                 │  │
│  │  ✓ Required human approvals attested (GitHub App)              │  │
│  │                                                                │  │
│  │  Result: PASS / FAIL + attestation of the gate decision       │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│  GUAC: Organizational Intelligence                                   │
│                                                                      │
│  Ingest:                                                             │
│  ├─ AflockGate review attestations (in-toto)                        │
│  ├─ Witness step attestations (in-toto)                             │
│  ├─ cosign image signatures (DSSE)                                  │
│  ├─ SBOMs (CycloneDX/SPDX) generated during build                  │
│  ├─ OSV vulnerability data                                          │
│  ├─ OpenSSF Scorecard results                                       │
│  └─ VEX documents                                                   │
│                                                                      │
│  Query (GraphQL):                                                    │
│  ├─ "Which repos are affected by CVE-2024-XXXX?"                   │
│  ├─ "Show me all PRs merged without a passing quality gate"         │
│  ├─ "What's the license risk across our organization?"              │
│  ├─ "Which artifacts lack build provenance?"                        │
│  └─ "Trace this container image back to its source commit"          │
│                                                                      │
│  Backend: PostgreSQL (ent) or in-memory (keyvalue)                  │
│  API: GraphQL — same interface regardless of backend                │
└─────────────────────────────────────────────────────────────────────┘
```

## Why GUAC Matters for AflockGate

GUAC occupies the **aggregation and synthesis** layer. AflockGate produces attestations at PR-time and build-time. GUAC consumes them and builds a graph that connects:

```
Source commit ──► PR attestation ──► Build attestation ──► Container image
      │                 │                    │                    │
      ▼                 ▼                    ▼                    ▼
  Scorecard        Vuln findings         SBOM              Image signature
                   Secret findings       Test results      Deployment record
                   License findings
```

Without GUAC, each attestation is an isolated document. With GUAC, you can ask **cross-cutting questions** like:
- "This CVE affects lodash@4.17.20. Which of our 200 repos use it, and which have deployed it to production?"
- "Show me all artifacts that were built without a passing AflockGate review."
- "What's the full provenance chain from this running container back to the source PR?"

### Integration Strategy

AflockGate does NOT embed GUAC. Instead:

1. **AflockGate produces** in-toto attestations (DSSE-wrapped, Sigstore-signed)
2. **GUAC ingests** those attestations via its collector framework
3. **AflockGate can query** GUAC's GraphQL API at deploy-time to make gate decisions

This keeps AflockGate lightweight (GitHub Action / CLI) while GUAC handles the heavy graph work as infrastructure.

### What to Build for GUAC Integration

- **GUAC collector for AflockGate**: A GUAC certifier plugin that understands AflockGate's predicateType and extracts the structured findings (vulns, secrets, licenses) into GUAC's graph nodes.
- **GUAC query in deploy gate**: At deploy-time, `aflockgate verify-pipeline` can query GUAC to check if all attestations exist and no blocking findings are present.
- **SBOM generation**: During build attestation, generate a CycloneDX/SPDX SBOM and ingest it into GUAC alongside the build attestation.

## How cosign Fits: Signature Verification as Default

Cosign's workflow from `sigstore/cosign` shows the pattern: **verify before you use**.

```yaml
# Before using ANY container image in your pipeline, verify its signature
- name: Verify base image
  run: |
    cosign verify ghcr.io/some-org/base-image:latest \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      --certificate-identity "https://github.com/some-org/base-image/.github/workflows/build.yml@refs/heads/main"
```

### What AflockGate Should Do with cosign

1. **PR-time: Dockerfile base image verification**
   - When a PR modifies a Dockerfile, parse `FROM` lines
   - Run `cosign verify` on each base image
   - If base image is unsigned or signature doesn't match policy → blocking finding

2. **PR-time: GitHub Actions verification**
   - When a PR modifies `.github/workflows/*.yml`, parse `uses:` lines
   - Verify that pinned actions have valid signatures or are from trusted orgs
   - Detect unpinned actions (`@main` instead of `@sha`) → warning

3. **Build-time: Sign produced artifacts**
   - After building a container image, `cosign sign` it with keyless signing
   - The signature is logged in Rekor → immutable evidence
   - The signed image reference goes into the build attestation

4. **Deploy-time: Verify before deploy**
   - Before deploying, `cosign verify` the image
   - Check that the image's signature chain links back to a passing AflockGate gate

### Policy Configuration

```json
{
  "cosign": {
    "verifyBaseImages": true,
    "verifyActions": true,
    "trustedIssuers": ["https://token.actions.githubusercontent.com"],
    "trustedIdentities": {
      "ghcr.io/my-org/*": ".github/workflows/build.yml@refs/heads/main"
    },
    "requirePinned": true
  }
}
```

## How nono-attest Fits: Config Integrity

nono-attest solves a critical gap: **What if someone tampers with the policy file itself?**

If an attacker weakens `.aflock.json` (e.g., removes `deniedFileGlobs`, sets `mode: "advisory"`), the gate passes even though the policy was compromised. nono's approach: **sign the policy file and verify the signature before applying it.**

### What AflockGate Should Do (nono-inspired)

1. **Sign policy files in CI**
   - When `.aflock.json` is modified on the main branch, sign it with Sigstore keyless
   - Store the signature bundle alongside the file (`.aflock.json.sig` or in-toto attestation)
   - The signing identity is bound to the repo + workflow + branch via Fulcio certificate

2. **Verify policy integrity before applying**
   - Before `loadPolicy()` reads `.aflock.json`, verify its signature
   - If signature is missing or invalid → use the hardcoded DEFAULT_POLICY (which is restrictive)
   - This prevents policy weakening attacks

3. **Extend to all config-as-code**
   - GitHub workflow files (`.github/workflows/*.yml`)
   - Dockerfile, Terraform, Helm charts
   - Any file that controls security-relevant behavior

### Trust Policy

```json
{
  "version": 1,
  "protected_files": [".aflock.json", ".github/workflows/*.yml"],
  "publishers": [
    {
      "name": "main branch CI",
      "issuer": "https://token.actions.githubusercontent.com",
      "repository": "my-org/my-repo",
      "workflow": ".github/workflows/sign-config.yml",
      "ref_pattern": "refs/heads/main"
    }
  ],
  "enforcement": "deny"
}
```

## Implementation Phases

### Phase 1: Supply Chain Scanners (Weeks 1-3)

Build the core scanning modules that run at PR-time and produce findings for the attestation.

#### 1.1 Secret Scanner (`src/scanners/secrets.ts`)

**What it does**: Scan diff content (not just filenames) for leaked credentials.

**Detection patterns**:
| Pattern | Regex | Severity |
|---------|-------|----------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | critical |
| AWS Secret Key | `(?i)aws_secret_access_key\s*=\s*\S{40}` | critical |
| GitHub Token | `gh[pousr]_[A-Za-z0-9_]{36,}` | critical |
| GitHub Fine-grained | `github_pat_[A-Za-z0-9_]{82}` | critical |
| Generic Private Key | `-----BEGIN (RSA\|EC\|DSA\|OPENSSH) PRIVATE KEY-----` | critical |
| JWT | `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}` | high |
| Connection String | `(?i)(postgres\|mysql\|mongodb\|redis)://[^\s]{10,}` | high |
| Generic API Key | `(?i)(api[_-]?key\|apikey\|api[_-]?secret)\s*[:=]\s*['"][^\s'"]{16,}` | medium |
| High entropy string | Shannon entropy > 4.5 in assignment context | low |

**Output**: `SecretFinding[]` — each finding has: pattern name, severity, file, line number (from diff), redacted match.

**Policy integration**:
```json
{
  "supplyChain": {
    "secrets": {
      "enabled": true,
      "severityThreshold": "high",
      "allowPatterns": [".*\\.test\\.ts$", ".*\\.example$"],
      "customPatterns": [
        { "name": "internal-token", "regex": "INTERNAL_[A-Z0-9]{32}", "severity": "critical" }
      ]
    }
  }
}
```

**Key design decisions**:
- Scan the **diff content**, not the full file (only new/modified lines contain new secrets)
- Provide **redacted matches** in findings (never expose the actual secret in attestations or PR comments)
- Support **allowPatterns** for test files and examples
- Support **custom patterns** for org-specific secrets

#### 1.2 Dependency Scanner (`src/scanners/deps.ts`)

**What it does**: Parse lockfiles from the PR diff, query OSV.dev for known vulnerabilities.

**Supported lockfiles** (start with the most common):
| File | Ecosystem | Parser Strategy |
|------|-----------|-----------------|
| `package-lock.json` | npm | JSON parse → extract `packages` map |
| `yarn.lock` | npm | Line-by-line parser |
| `go.sum` | Go | Line-by-line `module version hash` |
| `requirements.txt` | PyPI | Line-by-line `package==version` |
| `Cargo.lock` | crates.io | TOML parse → `[[package]]` entries |
| `pom.xml` | Maven | XML parse → `<dependency>` elements |
| `Gemfile.lock` | RubyGems | Section-based parser |

**Detection flow**:
1. From the PR diff, detect which lockfiles were modified
2. Parse the lockfile to extract `{name, version, ecosystem}` tuples
3. Diff against the base branch to identify **newly added** dependencies
4. Batch query [OSV.dev API](https://osv.dev/docs/) (`POST /v1/querybatch`)
5. For each vulnerability, fetch CVSS score, EPSS probability, and KEV status
6. Build transitive dependency graph from lockfile data

**Vulnerability scoring**:
```
risk_score = cvss_base * epss_probability * (is_kev ? 2.0 : 1.0) * depth_factor
depth_factor = 1.0 / (transitive_depth + 1)  // direct deps are riskier
```

**Output**: `DependencyFinding[]` — each finding has: package name, version, ecosystem, vulnerability IDs, CVSS, EPSS, is_kev, fix_version, transitive_depth.

#### 1.3 License Checker (`src/scanners/licenses.ts`)

**What it does**: For newly added dependencies, resolve the license and check against policy.

**License resolution**:
- npm: `https://registry.npmjs.org/{package}/{version}` → `.license`
- PyPI: `https://pypi.org/pypi/{package}/{version}/json` → `.info.license`
- Go: Query `pkg.go.dev` or use `go-licenses` output
- Fallback: Check `LICENSE` file in the dependency's repository

**License categories**:
| Category | Examples | Default Policy |
|----------|----------|----------------|
| Permissive | MIT, Apache-2.0, BSD-2-Clause, ISC | allow |
| Weak copyleft | LGPL-2.1, MPL-2.0, EPL-2.0 | warn |
| Strong copyleft | GPL-2.0, GPL-3.0 | deny (configurable) |
| Network copyleft | AGPL-3.0 | deny |
| Unknown | No license detected | warn |

**Output**: `LicenseFinding[]` — each finding has: package name, version, license SPDX ID, category, policy action (allow/warn/deny).

### Phase 2: Attestation Hardening (Weeks 3-5)

Migrate the attestation layer to industry-standard formats and signing.

#### 2.1 in-toto v1 Statement Format

Replace the current custom `Attestation` type with:

```typescript
interface InTotoStatementV1 {
  _type: "https://in-toto.io/Statement/v1";
  subject: Array<{
    name: string;
    digest: { sha256: string };
  }>;
  predicateType: string;
  predicate: Record<string, unknown>;
}

// AflockGate-specific predicate types:

// PR review attestation
// predicateType: "https://aflockgate.dev/attestation/review/v1"
interface ReviewPredicate {
  policy: Policy;
  evidence: Evidence;
  review: LLMReview;
  scanFindings: {
    secrets: SecretFinding[];
    dependencies: DependencyFinding[];
    licenses: LicenseFinding[];
  };
  gate: {
    decision: "pass" | "fail" | "advisory";
    reasons: string[];
  };
}

// Build step attestation (Witness-style)
// predicateType: "https://aflockgate.dev/attestation/step/v1"
interface StepPredicate {
  step: string;
  command: string;
  exitCode: number;
  environment: Record<string, string>;  // safe subset
  materials: Array<{ name: string; digest: { sha256: string } }>;
  products: Array<{ name: string; digest: { sha256: string } }>;
  startedAt: string;
  finishedAt: string;
}

// Approval attestation (gittuf-inspired)
// predicateType: "https://aflockgate.dev/attestation/approval/v1"
interface ApprovalPredicate {
  reviewer: string;
  reviewState: "approved" | "changes_requested" | "commented";
  commitSha: string;
  pullRequest: number;
  timestamp: string;
}
```

**Why in-toto**: It's the standard that GUAC, Witness, gittuf, SLSA, and cosign all understand. AflockGate attestations become immediately ingestible by any tool in the ecosystem.

**DSSE Envelope**: The in-toto statement is wrapped in a Dead Simple Signing Envelope:

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64 encoded in-toto statement>",
  "signatures": [
    {
      "keyid": "",
      "sig": "<base64 signature>"
    }
  ]
}
```

#### 2.2 Sigstore Keyless Signing

Replace static Ed25519 keys with Sigstore Fulcio + Rekor.

**How it works in GitHub Actions**:
1. Request OIDC token from GitHub (`id-token: write` permission)
2. Send OIDC token to Fulcio → receive short-lived X.509 certificate
3. Sign the DSSE envelope with the certificate's ephemeral key
4. Submit signature + certificate to Rekor → receive signed entry inclusion proof
5. Bundle = DSSE envelope + Fulcio certificate + Rekor inclusion proof

**The bundle proves**:
- WHO signed: The GitHub Actions workflow at a specific repo/branch/commit
- WHAT was signed: The in-toto statement with the review/scan findings
- WHEN it was signed: Rekor timestamp (within Fulcio certificate validity window)

**Fallback**: Keep Ed25519 signing for environments without OIDC (self-hosted runners, local testing, fork PRs).

**Library**: Use `sigstore-js` (the official Sigstore TypeScript SDK) — same library cosign and npm provenance use.

#### 2.3 Attestation Storage

Three options (support all, let users configure):

| Storage | Pros | Cons | Use When |
|---------|------|------|----------|
| **GitHub Actions artifacts** | Zero setup, already works | Ephemeral (90 day max retention) | Getting started |
| **OCI registry** (ghcr.io) | Standard, cosign-compatible, persistent | Requires container registry access | Production |
| **Git ref** (`refs/aflockgate/`) | Lives with the code, gittuf-compatible | Requires push permission | Audit trail |

For GUAC integration, OCI registry is ideal because GUAC already has an OCI collector.

### Phase 3: cosign Integration — Verify Everything (Weeks 4-6)

#### 3.1 Dockerfile Base Image Verification

When a PR modifies a Dockerfile:

```
Parse Dockerfile → Extract FROM images → cosign verify each → Report findings
```

**Implementation**: Parse Dockerfile `FROM` directives (including multi-stage builds), run `cosign verify` with the configured trusted issuers/identities, report unsigned or untrusted base images as blocking findings.

**Runner requirement**: `cosign` binary must be available. Provide a setup step or bundle it.

#### 3.2 GitHub Actions Pin Verification

When a PR modifies workflow files:

```
Parse workflow YAML → Extract uses: references → Check pinning → Report findings
```

**Checks**:
- Actions pinned to SHA (`@abc123`) → pass
- Actions pinned to tag (`@v4`) → warning (tags are mutable)
- Actions pinned to branch (`@main`) → blocking
- Actions from untrusted orgs → warning (configurable)

#### 3.3 Artifact Signing in Pipeline

The `aflockgate/witness-step` action (Phase 4) will call `cosign sign` after producing build artifacts:

```yaml
- name: Build and sign image
  uses: aflockgate/witness-step@v1
  with:
    step: build-image
    command: docker build -t ghcr.io/my-org/app:$SHA .
    cosign-sign: true  # signs the built image with keyless signing
```

### Phase 4: Config Integrity — nono-Inspired (Week 5)

#### 4.1 Policy File Signing

Add a workflow that signs `.aflock.json` whenever it changes on main:

```yaml
name: Sign AflockGate Config
on:
  push:
    branches: [main]
    paths: ['.aflock.json']

permissions:
  id-token: write
  contents: write

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aflockgate/sign-config@v1
        with:
          files: ".aflock.json"
```

This produces `.aflock.json.sigstore.json` (a Sigstore bundle) committed alongside the config.

#### 4.2 Policy Verification Before Application

In `loadPolicy()`, before applying the policy:

```
1. Read .aflock.json
2. Read .aflock.json.sigstore.json (if exists)
3. Verify signature against trusted publisher (repo + workflow + branch)
4. If signature invalid → use DEFAULT_POLICY (restrictive) + log warning
5. If signature valid → apply the policy from file
6. If no signature file → apply the policy but flag "unverified" in evidence
```

This is the nono pattern adapted for AflockGate: **the gate doesn't trust its own config unless it's signed**.

### Phase 5: Witness-Style Step Attestation (Weeks 6-8)

#### 5.1 `aflockgate/witness-step` Action

A companion GitHub Action that wraps any CI command:

```yaml
- name: Build
  uses: aflockgate/witness-step@v1
  with:
    step: build
    command: npm run build
    product-include-glob: "dist/**"
    attestation-store: oci  # or git-ref or artifact
```

**What it captures**:
- Step name, command, exit code, duration
- Materials: SHA256 of all input files (source checkout)
- Products: SHA256 of all output files matching the glob
- Environment: Runner OS, Node version, Git SHA (no secrets)
- Timestamp: Start and end time

**What it produces**: An in-toto Statement with `predicateType: https://aflockgate.dev/attestation/step/v1`, signed with Sigstore keyless.

#### 5.2 Pipeline Policy

Define the required attestation chain in `.aflock.json`:

```json
{
  "pipeline": {
    "requiredSteps": ["review", "build", "test"],
    "requiredAttestations": {
      "review": { "predicateType": "https://aflockgate.dev/attestation/review/v1" },
      "build": { "predicateType": "https://aflockgate.dev/attestation/step/v1" },
      "test": { "predicateType": "https://aflockgate.dev/attestation/step/v1", "exitCode": 0 }
    },
    "cosign": {
      "verifyImages": true,
      "trustedIssuers": ["https://token.actions.githubusercontent.com"]
    }
  }
}
```

### Phase 6: GitHub App Mode (Weeks 8-10)

#### 6.1 Webhook Server

Build a lightweight server that handles GitHub webhook events:

- `pull_request` → trigger the same scanning pipeline (but via webhook, not Actions)
- `pull_request_review` → record approval attestations (gittuf-style)
- `push` → detect direct pushes that bypass PR flow
- `check_suite` → report gate status

**Advantage over Actions**: Real-time response, cross-repo policy, approval tracking.

#### 6.2 Approval Attestation (gittuf-Inspired)

When a human approves a PR via GitHub's review UI:

1. Webhook receives `pull_request_review` event with `action: "submitted"`, `state: "approved"`
2. App creates an in-toto Statement with `predicateType: .../approval/v1`
3. Signs with the app's Sigstore identity
4. Pushes to `refs/aflockgate/attestations` in the repo

This creates an **immutable record** of who approved what — unlike GitHub's native reviews, which can be dismissed.

#### 6.3 Multi-Reviewer Quorum

Policy:
```json
{
  "approvals": {
    "required": 2,
    "requiredTeams": ["security"],
    "aiReviewWeight": 0.5
  }
}
```

The LLM review counts as a fractional "approval." Two humans + the AI = 2.5 approvals.

### Phase 7: Pipeline Verification Gate (Weeks 10-12)

#### 7.1 `aflockgate verify-pipeline` CLI / Action

The final gate before deployment:

```yaml
- name: Verify pipeline
  uses: aflockgate/verify-pipeline@v1
  with:
    image: ghcr.io/my-org/app:$SHA
    policy: .aflock.json
    guac-endpoint: https://guac.internal.company.com/query  # optional
```

**Verification checklist**:
1. PR review attestation exists → cosign verify-attestation
2. No critical vulnerabilities in scan findings
3. No secrets detected
4. License compliance passed
5. Build step attestation exists → cosign verify-attestation
6. Test step attestation exists with exit code 0
7. Container image signed → cosign verify
8. Base images verified → cosign verify
9. Policy file integrity verified (nono-style signature check)
10. Required human approvals attested (if GitHub App mode)

**GUAC integration**: If a GUAC endpoint is configured, query it to verify the full provenance chain exists in the graph. This enables cross-repo checks (e.g., "does the base image's pipeline also have passing attestations?").

#### 7.2 SLSA Level Mapping

Map the verification results to SLSA levels:

| SLSA Level | Requirement | AflockGate Coverage |
|------------|-------------|---------------------|
| Level 1 | Build process documented | Step attestation exists |
| Level 2 | Signed provenance | Sigstore-signed attestations |
| Level 3 | Hardened build platform | Environment attestation + isolated build |
| Level 4 | Two-party review | Approval attestations + quorum policy |

## Directory Structure (Planned)

```
aflockgate/
├── src/
│   ├── main.ts                     # Pipeline orchestration (existing)
│   ├── github.ts                   # GitHub API client (existing)
│   ├── policy.ts                   # Policy engine (extend)
│   ├── diff.ts                     # Diff processing (existing)
│   ├── llm.ts                      # LLM review (existing)
│   ├── schema.ts                   # Zod schemas (extend)
│   ├── output.ts                   # Artifacts & PR comment (extend)
│   │
│   ├── scanners/                   # NEW: Supply chain scanners
│   │   ├── secrets.ts              # Secret detection in diffs
│   │   ├── deps.ts                 # Dependency vulnerability scanner
│   │   ├── licenses.ts             # License compliance checker
│   │   ├── dockerfile.ts           # Dockerfile security checks
│   │   ├── actions.ts              # GitHub Actions pin verification
│   │   └── types.ts                # Shared scanner types
│   │
│   ├── attest/                     # EXTEND: Attestation layer
│   │   ├── intoto.ts               # in-toto v1 Statement builder
│   │   ├── dsse.ts                 # DSSE envelope wrapper
│   │   ├── sigstore.ts             # Sigstore keyless signing
│   │   ├── sign.ts                 # Ed25519 signing (existing, fallback)
│   │   ├── verify.ts               # Multi-format verification
│   │   ├── cosign.ts               # cosign CLI wrapper
│   │   ├── storage.ts              # OCI / git-ref / artifact storage
│   │   ├── types.ts                # Attestation types (existing, extend)
│   │   └── canonicalize.ts         # Canonical JSON (existing)
│   │
│   ├── config/                     # NEW: Config integrity
│   │   ├── sign.ts                 # Sign config files
│   │   └── verify.ts               # Verify config signatures
│   │
│   └── gate/                       # NEW: Pipeline verification
│       ├── verify.ts               # Verify full attestation chain
│       ├── slsa.ts                 # SLSA level assessment
│       └── guac.ts                 # GUAC GraphQL client
│
├── actions/                        # NEW: Companion actions
│   ├── witness-step/               # Witness-style step attestation
│   │   └── action.yml
│   ├── sign-config/                # nono-style config signing
│   │   └── action.yml
│   └── verify-pipeline/            # Deploy-time verification gate
│       └── action.yml
│
├── docs/
│   ├── design.md                   # Original design doc (existing)
│   └── roadmap.md                  # This file
│
├── action.yml                      # Main action (existing, extend)
└── package.json                    # Dependencies (extend)
```

## New Dependencies (Planned)

| Package | Purpose | Phase |
|---------|---------|-------|
| `sigstore` | Sigstore keyless signing (Fulcio + Rekor) | 2 |
| `@sigstore/bundle` | Bundle format handling | 2 |
| `oras` or `@oras/client` | OCI artifact push/pull | 2 |
| `js-yaml` | Parse GitHub Actions workflow files | 3 |
| `dockerfile-ast` | Parse Dockerfile FROM directives | 3 |
| `spdx-tools` | SBOM generation (optional) | 7 |

Lockfile parsers (Phase 1) are custom — no heavy dependencies needed.
OSV.dev is a REST API — use Node `fetch`.
License data comes from registry APIs — use Node `fetch`.

## Prioritized Implementation Order

| # | Module | Impact | Effort | Depends On |
|---|--------|--------|--------|------------|
| 1 | Secret Scanner | Highest immediate value — stops credential leaks | Low (regex + entropy) | Nothing |
| 2 | Dependency Scanner + OSV | High — catches CVEs before merge | Medium (lockfile parsers + API) | Nothing |
| 3 | in-toto attestation format | Foundation for interop with GUAC, Witness, cosign | Medium (refactor attest/) | Nothing |
| 4 | Sigstore keyless signing | Eliminates key management; enables trust chain | Medium (sigstore-js integration) | #3 |
| 5 | License Checker | Low effort, high compliance value | Low (registry API queries) | #2 (shares dep data) |
| 6 | cosign base image verification | Blocks unsigned images in Dockerfiles | Low (CLI wrapper) | #4 |
| 7 | Config integrity (nono-style) | Prevents policy tampering | Low (reuse #4 signing) | #4 |
| 8 | Actions pin verification | Blocks mutable action references | Low (YAML parser) | Nothing |
| 9 | Witness-style step attestation | Completes build provenance | Medium (new action) | #3, #4 |
| 10 | GitHub App mode | Unlocks approval tracking, webhooks | High (server + deployment) | #3, #4 |
| 11 | Pipeline verification gate | The full quality gate | Medium (verification logic) | #3, #4, #9 |
| 12 | GUAC integration | Organizational intelligence | Medium (GraphQL client + collector) | #3, #11 |

## What This Unlocks

When fully built, a team using AflockGate gets:

- **PR opens** → Secret scan + dependency scan + license check + LLM review + policy check → signed in-toto attestation
- **Human approves** → Approval attestation recorded (immutable)
- **CI builds** → Each step attested (Witness-style) → artifacts signed (cosign)
- **Deploy gate** → Verify full chain: review + approvals + scans + build + signatures → PASS/FAIL
- **Org dashboard** → GUAC query: "What's our risk posture across all repos?"

One `.aflock.json`, one platform, one attestation chain, one graph.
