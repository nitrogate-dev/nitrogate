# NitroGate Test Cases

Ready-to-use test files for every NitroGate scanner. Each folder triggers a specific scanner to demonstrate its detection capabilities.

## Quick Start

```bash
# Clone your test-app repo
git clone git@github.com:nitrogate-dev/test-app.git /tmp/test-app

# Run the automated script
./create-test-prs.sh /tmp/test-app

# Choose option 7 to create ALL test branches
# Then go to GitHub and create PRs from each branch
```

## Test Cases

### 1. Secrets Scanner (`01-secrets/`)
**File:** `bad-code.ts`

| Secret Type | Pattern | Expected Severity |
|---|---|---|
| AWS Access Key ID | `AKIA...` prefix | Critical |
| GitHub Personal Access Token | `ghp_...` prefix | Critical |
| RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` | Critical |
| Database Connection String | `postgresql://user:pass@host` | High |

**Expected result:** Quality Gate FAIL, 4+ findings with inline comments on each line.

---

### 2. Workflow Security (`02-workflow-security/`)
**File:** `.github/workflows/vulnerable-ci.yml`

| Vulnerability | What NitroGate Detects | Expected Severity |
|---|---|---|
| Script Injection | `${{ github.event.pull_request.title }}` in `run:` | Critical |
| Pwn Request | `pull_request_target` + checkout of PR head SHA | Critical |
| Unpinned Action (branch) | `actions/checkout@main` | High |
| Excessive Permissions | `permissions: write-all` | High |
| Secrets in Logs | `echo ${{ secrets.DEPLOY_KEY }}` | Critical |

**Expected result:** Quality Gate FAIL, 5+ findings across multiple vulnerability types.

---

### 3. NPM Supply Chain (`03-npm-supply-chain/`)
**Files:** `package.json` + `package-lock.json`

| Check | Package | Why Flagged | Expected Severity |
|---|---|---|---|
| Compromised | `event-stream@3.3.6` | Hijacked — cryptocurrency wallet theft | Critical |
| Compromised | `crossenv@1.0.0` | Typosquat of cross-env — credential theft | Critical |
| Compromised | `flatmap-stream@0.1.1` | Malicious payload for crypto wallets | Critical |
| Typosquat | `expres@4.18.0` | Similar to `express` | High |

**Expected result:** Quality Gate FAIL, 4+ findings.

---

### 4. Dependency Vulnerabilities (`04-dependencies/`)
**File:** `package-lock.json`

| Package | Version | Known CVEs | Expected Severity |
|---|---|---|---|
| `lodash` | 4.17.11 | CVE-2019-10744 (Prototype Pollution) | High/Critical |
| `minimist` | 1.2.5 | CVE-2021-44906 (Prototype Pollution) | High |
| `axios` | 0.21.1 | CVE-2021-3749 (ReDoS) | Medium/High |
| `node-fetch` | 2.6.0 | CVE-2022-0235 (Info Leak) | Medium |
| `json5` | 2.2.1 | CVE-2022-46175 (Prototype Pollution) | High |

**Expected result:** Quality Gate FAIL, multiple CVE findings via OSV.dev API.

---

### 5. License Check (`05-license-check/`)
**File:** `package-lock.json`

| Package | License | Category | Expected Severity |
|---|---|---|---|
| Various | GPL-2.0/GPL-3.0 | Strong Copyleft | High |
| Various | AGPL-3.0 | Network Copyleft | High |

**Expected result:** Quality Gate FAIL if denied licenses found in policy.

---

### 6. All Scanners (`06-all-scanners/`)
**Files:** `bad-code.ts` + `.github/workflows/ci.yml` + `package-lock.json`

Triggers ALL 5 scanners simultaneously:
- Secrets: AWS key + GitHub token
- Workflow: Script injection + pwn request + unpinned actions + excessive perms
- NPM Supply Chain: event-stream (compromised)
- Dependencies: lodash CVE + axios CVE
- Licenses: checked via lockfile

**Expected result:** Quality Gate FAIL, 10+ findings across all scanners, with inline review comments on each flagged line.

## Manual Testing (without the script)

If you prefer to test manually:

```bash
cd /path/to/test-app

# Example: test secrets scanner
git checkout -b test/secrets
cp /path/to/nitrogate/examples/test-cases/01-secrets/bad-code.ts .
git add bad-code.ts
git commit -m "Add code with secrets"
git push -u origin test/secrets
# Then create PR on GitHub
```
