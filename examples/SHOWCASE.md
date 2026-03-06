# NitroGate — Hackathon Showcase

## One-liner

**NitroGate is an automated supply chain quality gate that scans every PR for secrets, vulnerable dependencies, NPM supply chain attacks, and insecure CI workflows — then produces signed attestations and feeds results into GUAC for org-wide visibility.**

---

## The Problem (Why This Matters)

### What we face today

| Problem | Impact | Frequency |
|---|---|---|
| Secrets committed to repos | Credential theft, data breaches | **[Weekly]** Every team has done it |
| Vulnerable dependencies merged | CVEs in production | **[Daily]** New CVEs every day |
| NPM supply chain attacks | Malware in `node_modules` | **[Monthly]** event-stream, ua-parser-js, colors |
| Insecure GitHub Actions | Script injection → repo takeover | **[Common]** Most workflows are vulnerable |
| No proof of gate results | "Trust me, CI passed" | **[Always]** No cryptographic evidence |
| No org-wide visibility | "Which repos are affected?" | **[Always]** Every incident requires manual triage |

### Real incidents NitroGate would have caught

| Incident | Year | What Happened | NitroGate Scanner |
|---|---|---|---|
| event-stream | 2018 | Compromised npm package stole Bitcoin wallet keys | NPM Supply Chain |
| ua-parser-js | 2021 | Crypto miner injected into popular package | NPM Supply Chain |
| Codecov bash uploader | 2021 | Modified script exfiltrated CI secrets | Workflow Security |
| colors/faker | 2022 | Maintainer sabotaged own packages | NPM Supply Chain |
| PyTorch nightly | 2022 | Dependency confusion attack | Dependencies |

---

## What NitroGate Does

```
Developer opens PR
        ↓
NitroGate runs automatically (GitHub Action)
        ↓
┌──────────────────────────────────────────┐
│  5 scanners run in parallel:             │
│                                          │
│  🔐 Secret Scanner (17 patterns + entropy)│
│  📦 Dependency Scanner (OSV.dev API)      │
│  ⚡ NPM Supply Chain (compromised/typo)   │
│  🔧 Workflow Security (injection/Pwn)     │
│  📄 License Compliance (GPL/AGPL block)   │
└──────────────────────────────────────────┘
        ↓
Gate Decision: PASS / FAIL / ADVISORY
        ↓
┌──────────────────────────────────────────┐
│  📝 PR Comment with findings             │
│  ✍️  Ed25519 signed in-toto attestation   │
│  📊 GUAC metadata (org intelligence)     │
└──────────────────────────────────────────┘
```

---

## Tech Stack

| Component | Technology | Why |
|---|---|---|
| Core engine | **Go** | Fast, single binary, native crypto, Sigstore ecosystem |
| Attestation format | **in-toto v1 + DSSE** | Industry standard, GUAC-compatible |
| Signing | **Ed25519** | Fast, small keys, deterministic |
| Vuln database | **OSV.dev** | Google-backed, 470K+ vulns, all ecosystems |
| Org intelligence | **GUAC** | Graph DB for software security metadata |
| Deployment | **GitHub Action (Docker)** | Zero setup for teams |

---

## Demo Script (5 minutes)

### Act 1: The Problem (1 min)

> "Right now, a developer can open a PR that adds an AWS key, a compromised npm package, and an insecure CI workflow — and it will merge if CI passes. There's no unified gate, no proof it was checked, and no way to ask 'which repos across the org have this problem?'"

### Act 2: NitroGate in Action (2 min)

```bash
# Show all tests passing
cd nitrogate && go test ./internal/... -v

# Show the binary builds
go build -o bin/nitrogate ./cmd/nitrogate/

# Show test attestation generation
go run test-guac/generate_attestation.go

# Show the attestation (in-toto v1 + DSSE)
cat test-guac/attestation.json | python3 -m json.tool
```

### Act 3: GUAC — Org Intelligence (2 min)

```bash
# Run the GUAC demo (ingests data for 3 repos)
./examples/06-guac-integration/demo-queries.sh

# Key query: "Which repos are failing?"
curl -s http://localhost:9080/query -H "Content-Type: application/json" -d '{
  "query": "{ HasMetadata(hasMetadataSpec: {key: \"nitrogate:decision\", value: \"FAIL\"}) { value justification subject { ... on Package { namespaces { names { name } } } } } }"
}' | python3 -m json.tool
```

> "With one query, we can see every repo across the org that has a failing quality gate, what the findings were, and when it happened. No Slack messages, no spreadsheets."

### Act 4: Integration with Quality Gates (30 sec)

> "NitroGate also integrates with our existing quality gate system. We added three new TypeScript gates — NPM supply chain, workflow security, and secret scanning — that plug directly into the existing dashboard and bot."

---

## Hackathon Theme Alignment

### Quality Enhancement

- **Automated scanning**: 5 parallel scanners catch issues humans miss
- **Cryptographic proof**: Every gate result is signed (Ed25519 + in-toto)
- **Org-wide visibility**: GUAC enables "Which repos are affected?" queries

### Velocity & Productivity

- **Zero setup**: Add one workflow file and a `.nitrogate.json`
- **Parallel scanners**: All 5 run concurrently (~2-3 seconds total)
- **Self-serve**: Developers get immediate, actionable feedback on the PR

### System Performance Early Detection

- **NPM supply chain**: Catches attacks within hours (cooldown period)
- **Dependency vulns**: OSV.dev updates within hours of CVE publication
- **Workflow security**: Prevents CI/CD exploitation before it happens

---

## What's Built (Proof of Work)

| Component | Status | LOC | Tests |
|---|---|---|---|
| Secret Scanner (Go) | ✅ Done | ~200 | 4 tests |
| Dependency Scanner (Go) | ✅ Done | ~300 | Unit tests |
| NPM Supply Chain Scanner (Go) | ✅ Done | ~370 | 3 tests |
| Workflow Security Scanner (Go) | ✅ Done | ~250 | Unit tests |
| License Scanner (Go) | ✅ Done | ~200 | Unit tests |
| Gate Evaluator | ✅ Done | ~130 | 7 tests |
| In-toto Attestation Builder | ✅ Done | ~130 | 5 tests |
| Ed25519 Signer/Verifier | ✅ Done | ~100 | 4 tests |
| GUAC Client (GraphQL) | ✅ Done | ~200 | Manual |
| PR Comment Generator | ✅ Done | ~170 | — |
| Docker + GitHub Action | ✅ Done | ~50 | — |
| Quality Gate TS (NPM) | ✅ Done | ~290 | Manual |
| Quality Gate TS (Workflows) | ✅ Done | ~200 | Manual |
| Quality Gate TS (Secrets) | ✅ Done | ~200 | Manual |
| **Total** | | **~2,800** | **23+ tests** |

---

## Quick Test Commands

```bash
# Run all Go tests (no network/docker needed)
go test ./internal/... -v

# Build binary
go build -o bin/nitrogate ./cmd/nitrogate/

# Generate attestation
go run test-guac/generate_attestation.go

# Start GUAC
cd deploy && docker compose -f guac-demo-compose.yaml -p guac up -d

# Run full demo
./examples/07-full-pr-simulation/simulate.sh

# Run GUAC demo queries
./examples/06-guac-integration/demo-queries.sh
```

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                       GitHub PR                             │
│  Developer pushes code → PR opened/updated                  │
└────────────────────────────┬────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────┐
│                    NitroGate (Go Binary)                     │
│                                                             │
│  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ ┌─────┐ │
│  │ Secrets  │ │   Deps   │ │ NPM S/C  │ │Workflow│ │Lic. │ │
│  │ Scanner  │ │ Scanner  │ │ Scanner  │ │Scanner │ │Scan │ │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └───┬────┘ └──┬──┘ │
│       └──────────┬──┴────────────┴───────────┴─────────┘    │
│                  ↓                                          │
│  ┌───────────────────────────────────┐                      │
│  │  Gate Evaluator (PASS/FAIL/ADV)   │                      │
│  └─────────────┬─────────────────────┘                      │
│                ↓                                            │
│  ┌─────────────────────┐  ┌──────────────────────────────┐  │
│  │  Ed25519 Signer     │  │  PR Comment Generator        │  │
│  │  (in-toto + DSSE)   │  │  (Markdown with findings)    │  │
│  └─────────┬───────────┘  └──────────────┬───────────────┘  │
└────────────┼─────────────────────────────┼──────────────────┘
             ↓                             ↓
┌──────────────────────┐    ┌──────────────────────────────┐
│  GUAC (GraphQL)      │    │  GitHub PR Comment           │
│  "Which repos fail?" │    │  + Artifacts (JSON)          │
└──────────────────────┘    └──────────────────────────────┘
```
