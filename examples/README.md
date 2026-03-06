# NitroGate Examples

Complete test scenarios demonstrating every NitroGate capability. Each example includes test data, expected output, and step-by-step instructions.

## Quick Start

```bash
# Run all Go tests (no Docker, no network needed for most)
cd /path/to/nitrogate
go test ./internal/... -v

# Run the full simulation (includes GUAC if Docker is running)
./examples/07-full-pr-simulation/simulate.sh
```

## Examples

| # | Example | What It Tests | Docker Needed? |
|---|---|---|---|
| 01 | [Secret Scanning](01-secret-scanning/) | AWS keys, GitHub tokens, high-entropy strings | No |
| 02 | [NPM Supply Chain](02-npm-supply-chain/) | Compromised packages, typosquatting, install scripts | No |
| 03 | [Workflow Security](03-workflow-security/) | Script injection, Pwn Request, unpinned actions | No |
| 04 | [Dependency Scanning](04-dependency-scanning/) | CVE detection via OSV.dev | No (network for API) |
| 05 | [License Check](05-license-check/) | GPL/AGPL detection, copyleft warnings | No (network for API) |
| 06 | [GUAC Integration](06-guac-integration/) | Org-wide security queries | **Yes** |
| 07 | [Full PR Simulation](07-full-pr-simulation/) | End-to-end demo with all scanners | Optional |

## Setup Prerequisites

| Requirement | For | Install |
|---|---|---|
| Go 1.22+ | Core engine, tests | `brew install go` |
| Docker | GUAC integration | Docker Desktop |
| Python 3 | JSON pretty-print | Usually pre-installed |

## Hackathon Demo

See [SHOWCASE.md](SHOWCASE.md) for the presentation-ready demo script with talking points.

## Testing on a Personal GitHub Repo

1. Create a GitHub org (free): https://github.com/organizations/plan
2. Create a test repo in the org
3. Copy `.nitrogate.json` from `examples/07-full-pr-simulation/`
4. Copy `.github/workflows/nitrogate.yml` from `examples/07-full-pr-simulation/`
5. Generate a signing key: `openssl rand -base64 32`
6. Add it as a repo secret: `NITRO_SIGNING_KEY_B64`
7. Open a PR with intentionally bad code (use files from examples 01-05)
8. Watch NitroGate comment on the PR
