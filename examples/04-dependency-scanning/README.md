# Example 04: Dependency Vulnerability Scanning

## What This Tests

NitroGate's dependency scanner:
1. **Parses lockfiles** from PR diffs (package-lock.json, go.sum, requirements.txt, Cargo.lock, Gemfile.lock)
2. **Queries OSV.dev API** for known vulnerabilities
3. Reports CVEs with severity, affected versions, and fix versions

## Supported Ecosystems

| Ecosystem | Lockfile | Registry |
|---|---|---|
| npm | `package-lock.json` | OSV.dev (npm) |
| Go | `go.sum` | OSV.dev (Go) |
| Python | `requirements.txt` | OSV.dev (PyPI) |
| Rust | `Cargo.lock` | OSV.dev (crates.io) |
| Ruby | `Gemfile.lock` | OSV.dev (RubyGems) |

## Test Data

`package-lock.json` contains dependencies with known vulnerabilities:
- `lodash@4.17.20` — CVE-2021-23337 (Command Injection, Critical)
- `minimist@1.2.5` — CVE-2021-44906 (Prototype Pollution, Critical)

## How to Run

```bash
cd /path/to/nitrogate
go test ./internal/scanner/ -run TestDepsScanner -v
```

**Note**: The dependency scanner requires network access to query OSV.dev. Tests that hit the live API are integration tests.

## Expected Findings

| Package | CVE | Severity | Fix Version |
|---|---|---|---|
| lodash@4.17.20 | CVE-2021-23337 | Critical | 4.17.21 |
| minimist@1.2.5 | CVE-2021-44906 | Critical | 1.2.6 |

## How It Works

1. Scanner extracts added lines from the PR diff
2. Identifies lockfile format and parses package name + version
3. Batches queries to OSV.dev API (`POST /v1/query`)
4. Maps OSV severity to NitroGate severity levels
5. Returns findings with remediation (upgrade to fix version)

## Production Impact

- OSV.dev covers **470,000+ vulnerabilities** across all ecosystems
- Queries are batched for performance (~200ms for 50 packages)
- Severity threshold is configurable: block on Critical+High, warn on Medium
