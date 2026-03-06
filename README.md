# NitroGate

**Supply Chain Quality Gate with Signed Attestations & Organizational Intelligence**

NitroGate is a GitHub Action and CLI tool that enforces supply chain security policies on every pull request — scanning for secrets, vulnerable dependencies, workflow security issues, NPM supply chain attacks, and license violations — then producing cryptographically signed in-toto attestations and feeding results into GUAC for org-wide visibility.

## What It Solves

| Problem | How NitroGate Helps |
|---|---|
| Secrets leaked in PRs | 17 regex patterns + high-entropy detection catch AWS keys, tokens, private keys |
| Vulnerable dependencies | Parses lockfiles, queries OSV.dev for known CVEs |
| NPM supply chain attacks | Detects compromised packages, typosquatting, suspicious install scripts, new-package cooldown |
| Insecure GitHub Actions | Flags script injection, Pwn Request, unpinned actions, excessive permissions |
| License compliance | Blocks AGPL/GPL, warns on copyleft, resolves from registries |
| No proof of gate results | Ed25519-signed in-toto attestations — tamper-evident, GUAC-compatible |
| No org-wide visibility | GUAC integration: "Which repos have failing gates?" in one query |

## Quick Start

### 1. Add the workflow

Create `.github/workflows/nitrogate.yml`:

```yaml
name: NitroGate Quality Gate
on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: nitrogate/nitrogate@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          NITRO_SIGNING_KEY_B64: ${{ secrets.NITRO_SIGNING_KEY_B64 }}
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: nitrogate-artifacts
          path: nitrogate-artifacts/
```

### 2. Create a policy file

Add `.nitrogate.json` to your repo root:

```json
{
  "mode": "gate",
  "secrets": {
    "enabled": true,
    "severityThreshold": "high",
    "allowFiles": ["**/*.test.*", "**/*.spec.*"]
  },
  "dependencies": {
    "enabled": true,
    "severityThreshold": "high",
    "npmSupplyChain": {
      "cooldownDays": 7,
      "checkCompromised": true,
      "checkTyposquatting": true,
      "checkInstallScripts": true
    }
  },
  "workflows": {
    "enabled": true,
    "requirePinnedActions": true,
    "checkScriptInjection": true,
    "checkPwnRequest": true
  },
  "licenses": {
    "enabled": true,
    "denied": ["AGPL-3.0", "GPL-3.0"]
  },
  "attestation": {
    "format": "intoto-v1",
    "signing": "ed25519"
  },
  "guac": {
    "enabled": false,
    "endpoint": "http://localhost:8080/query"
  }
}
```

### 3. Generate a signing key

```bash
openssl rand -base64 32
```

Add the output as a GitHub repository secret named `NITRO_SIGNING_KEY_B64`.

### 4. Open a PR

NitroGate will:
1. Load and evaluate the policy
2. Run all scanners in parallel (secrets, deps, workflows, licenses, NPM supply chain)
3. Evaluate the quality gate (PASS / FAIL / ADVISORY)
4. Sign an in-toto attestation with Ed25519
5. Post a detailed PR comment with findings
6. Push results to GUAC (if enabled)

## Scanners

| Scanner | What It Catches | Severity |
|---|---|---|
| **Secrets** | AWS keys, GitHub tokens, private keys, high-entropy strings | Critical |
| **Dependencies** | Known CVEs via OSV.dev API | Critical-High |
| **NPM Supply Chain** | Compromised packages, typosquatting, cooldown, install scripts | Critical-Medium |
| **Workflow Security** | Script injection, Pwn Request, unpinned actions, excessive permissions | Critical-Medium |
| **Licenses** | GPL/AGPL violations, copyleft warnings | High-Medium |

## GUAC Integration

NitroGate pushes gate results into [GUAC](https://github.com/guacsec/guac) as `HasMetadata` entries, enabling org-wide queries:

```graphql
# "Show me all repos with failing quality gates"
{
  HasMetadata(hasMetadataSpec: {key: "nitrogate:decision", value: "FAIL"}) {
    id key value justification timestamp
    subject { ... on Package { type namespaces { namespace names { name } } } }
  }
}
```

## Running Locally

```bash
go build -o bin/nitrogate ./cmd/nitrogate/
go test ./internal/...
```

See [examples/](examples/) for complete test scenarios and [docs/testing-guide.md](docs/testing-guide.md) for the full setup guide.

## Architecture

See [docs/design-v2.md](docs/design-v2.md) for the full Go + GUAC design document.

## License

MIT
