# Example 01: Secret Scanning

## What This Tests

NitroGate's secret scanner detects credentials leaked in PR diffs using:
- **17 regex patterns** for AWS keys, GitHub tokens, Slack webhooks, private keys, etc.
- **Shannon entropy detection** for high-entropy strings (API keys, tokens)
- **File allowlisting** to skip test fixtures

## Test Data

The `bad-diff.patch` file simulates a PR diff containing:
1. An AWS Access Key ID
2. A GitHub Personal Access Token
3. A high-entropy string that looks like an API key

## How to Run

```bash
cd /path/to/nitrogate
go test ./internal/scanner/ -run TestSecretScanner -v
```

## Expected Output

```
=== RUN   TestSecretScanner_BasicDetection
--- PASS: TestSecretScanner_BasicDetection (0.00s)
=== RUN   TestSecretScanner_AllowFiles
--- PASS: TestSecretScanner_AllowFiles (0.00s)
=== RUN   TestSecretScanner_HighEntropy
--- PASS: TestSecretScanner_HighEntropy (0.00s)
```

The scanner should detect:
- **AWS Access Key** (Critical) — matches `AKIA[0-9A-Z]{16}` pattern
- **GitHub Token** (Critical) — matches `ghp_[a-zA-Z0-9]{36}` pattern
- **High-Entropy String** (High) — Shannon entropy > 4.5

## What the PR Comment Looks Like

```markdown
## NitroGate Quality Gate

❌ Quality Gate: **FAIL** — 2 critical, 1 high (5 scanners)

❌ **Secrets** — 3 finding(s) (5ms)
  🔴 **AWS Access Key Detected**: AKIA***REDACTED*** found in config.ts
    📄 `config.ts`:12
    💡 Remove the key and rotate it immediately
  🔴 **GitHub Token Detected**: ghp_***REDACTED*** found in deploy.sh
    📄 `deploy.sh`:7
    💡 Revoke the token in GitHub Settings → Developer settings
  🟠 **High Entropy String**: Possible API key or token
    📄 `utils/api.ts`:34
```

## Key Design Decisions

- Secrets are **always Critical severity** (AWS, GitHub tokens) or **High** (entropy)
- Detected values are **redacted** in PR comments — only first 4 chars shown
- Test files (`*.test.*`, `*.spec.*`) are allowlisted by default
