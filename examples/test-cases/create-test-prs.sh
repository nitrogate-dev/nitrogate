#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_APP_DIR="${1:?Usage: $0 /path/to/test-app}"

if [ ! -d "$TEST_APP_DIR/.git" ]; then
  echo "Error: $TEST_APP_DIR is not a git repo"
  exit 1
fi

cd "$TEST_APP_DIR"
DEFAULT_BRANCH=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@' || echo "main")

echo "=== NitroGate Test PR Creator ==="
echo "Test app: $TEST_APP_DIR"
echo "Base branch: $DEFAULT_BRANCH"
echo ""

create_pr_branch() {
  local BRANCH=$1
  local TITLE=$2
  local SOURCE_DIR=$3

  echo "--- Creating branch: $BRANCH ---"
  git checkout "$DEFAULT_BRANCH" 2>/dev/null
  git pull origin "$DEFAULT_BRANCH" 2>/dev/null || true

  git checkout -B "$BRANCH"

  cp -r "$SOURCE_DIR"/* . 2>/dev/null || true

  if [ -d "$SOURCE_DIR/.github" ]; then
    mkdir -p .github/workflows
    cp -r "$SOURCE_DIR/.github/workflows/"* .github/workflows/ 2>/dev/null || true
  fi

  git add -A
  git commit -m "$TITLE" --allow-empty 2>/dev/null || echo "  (no changes to commit)"
  git push -u origin "$BRANCH" --force 2>/dev/null

  echo "  Branch '$BRANCH' pushed."
  echo "  Create PR at: https://github.com/nitrogate-dev/test-app/compare/$DEFAULT_BRANCH...$BRANCH"
  echo ""
}

generate_secrets_file() {
  local TARGET=$1
  cat > "$TARGET" << 'SECRETSEOF'
// NitroGate Secrets Scanner test file
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGT6AjVJlAkBBE0K1pGf
-----END RSA PRIVATE KEY-----`;
const DB_CONN = "postgresql://admin:supersecretpassword@db.example.com:5432/production";
SECRETSEOF
}

echo "Which test case do you want to create?"
echo ""
echo "  1) Secrets Scanner      — AWS key, GitHub token, private key, DB conn string"
echo "  2) Workflow Security     — Script injection, pwn request, unpinned actions"
echo "  3) NPM Supply Chain     — Compromised packages (event-stream, crossenv)"
echo "  4) Dependency Vulns     — Vulnerable lodash, axios, minimist, node-fetch"
echo "  5) License Check        — GPL-licensed dependencies"
echo "  6) ALL scanners at once — Secrets + Workflow + NPM + Deps combined"
echo "  7) Create ALL branches  — One branch per test case"
echo ""
read -p "Choose [1-7]: " CHOICE

case $CHOICE in
  1) create_pr_branch "test/secrets" "Add code with hardcoded secrets" "$SCRIPT_DIR/01-secrets" ;;
  2) create_pr_branch "test/workflow-security" "Add vulnerable CI workflow" "$SCRIPT_DIR/02-workflow-security" ;;
  3) create_pr_branch "test/npm-supply-chain" "Add compromised npm packages" "$SCRIPT_DIR/03-npm-supply-chain" ;;
  4) create_pr_branch "test/vulnerable-deps" "Add dependencies with known CVEs" "$SCRIPT_DIR/04-dependencies" ;;
  5) create_pr_branch "test/license-check" "Add GPL-licensed dependencies" "$SCRIPT_DIR/05-license-check" ;;
  6) create_pr_branch "test/all-scanners" "Add files triggering all scanners" "$SCRIPT_DIR/06-all-scanners" ;;
  7)
    create_pr_branch "test/secrets" "Add code with hardcoded secrets" "$SCRIPT_DIR/01-secrets"
    create_pr_branch "test/workflow-security" "Add vulnerable CI workflow" "$SCRIPT_DIR/02-workflow-security"
    create_pr_branch "test/npm-supply-chain" "Add compromised npm packages" "$SCRIPT_DIR/03-npm-supply-chain"
    create_pr_branch "test/vulnerable-deps" "Add dependencies with known CVEs" "$SCRIPT_DIR/04-dependencies"
    create_pr_branch "test/license-check" "Add GPL-licensed dependencies" "$SCRIPT_DIR/05-license-check"
    create_pr_branch "test/all-scanners" "Add files triggering all scanners" "$SCRIPT_DIR/06-all-scanners"
    echo "=== All 6 branches created! Now create PRs from each branch on GitHub. ==="
    ;;
  *) echo "Invalid choice"; exit 1 ;;
esac

echo "Done! Go to GitHub and create PRs from the branches above."
echo "NitroGate will automatically scan each PR and post results."
