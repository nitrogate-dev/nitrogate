package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkflowScanner_ScriptInjection(t *testing.T) {
	diff := `diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- /dev/null
+++ b/.github/workflows/ci.yml
@@ -0,0 +1,12 @@
+name: CI
+on: issues
+jobs:
+  greet:
+    runs-on: ubuntu-latest
+    steps:
+      - name: Greet
+        run: |
+          echo "Issue: ${{ github.event.issue.title }}"
+          echo "Body: ${{ github.event.issue.body }}"`

	s := NewWorkflowScanner(true, true, true, true, []string{"actions"})
	result := s.Scan(&ScanContext{
		Diff:         diff,
		ChangedFiles: []string{".github/workflows/ci.yml"},
	})

	found := 0
	for _, f := range result.Findings {
		if f.RuleID == "script-injection" {
			found++
			assert.Equal(t, SeverityCritical, f.Severity)
			assert.Contains(t, f.Remediation, "environment variable")
		}
	}
	assert.GreaterOrEqual(t, found, 2, "Should detect both injection points")
}

func TestWorkflowScanner_PwnRequest(t *testing.T) {
	diff := `diff --git a/.github/workflows/review.yml b/.github/workflows/review.yml
--- /dev/null
+++ b/.github/workflows/review.yml
@@ -0,0 +1,10 @@
+name: Review
+on: pull_request_target
+jobs:
+  review:
+    runs-on: ubuntu-latest
+    steps:
+      - uses: actions/checkout@v4
+        with:
+          ref: ${{ github.event.pull_request.head.sha }}
+      - run: npm test`

	s := NewWorkflowScanner(true, true, true, true, []string{"actions"})
	result := s.Scan(&ScanContext{
		Diff:         diff,
		ChangedFiles: []string{".github/workflows/review.yml"},
	})

	found := false
	for _, f := range result.Findings {
		if f.RuleID == "pwn-request" {
			found = true
			assert.Equal(t, SeverityCritical, f.Severity)
			assert.Contains(t, f.Detail, "pull_request_target")
		}
	}
	assert.True(t, found, "Should detect Pwn Request vulnerability")
}

func TestWorkflowScanner_UnpinnedAction_Branch(t *testing.T) {
	diff := `diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- /dev/null
+++ b/.github/workflows/ci.yml
@@ -0,0 +1,8 @@
+name: CI
+on: push
+jobs:
+  build:
+    runs-on: ubuntu-latest
+    steps:
+      - uses: some-org/dangerous-action@main
+      - run: echo hello`

	s := NewWorkflowScanner(false, false, false, true, []string{"actions"})
	result := s.Scan(&ScanContext{
		Diff:         diff,
		ChangedFiles: []string{".github/workflows/ci.yml"},
	})

	found := false
	for _, f := range result.Findings {
		if f.RuleID == "unpinned-action-branch" {
			found = true
			assert.Equal(t, SeverityHigh, f.Severity)
			assert.Contains(t, f.Detail, "main")
		}
	}
	assert.True(t, found, "Should flag branch-pinned actions")
}

func TestWorkflowScanner_UnpinnedAction_Tag(t *testing.T) {
	diff := `diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- /dev/null
+++ b/.github/workflows/ci.yml
@@ -0,0 +1,8 @@
+name: CI
+on: push
+jobs:
+  build:
+    runs-on: ubuntu-latest
+    steps:
+      - uses: unknown-org/some-action@v2
+      - run: echo hello`

	s := NewWorkflowScanner(false, false, false, true, []string{"actions"})
	result := s.Scan(&ScanContext{
		Diff:         diff,
		ChangedFiles: []string{".github/workflows/ci.yml"},
	})

	found := false
	for _, f := range result.Findings {
		if f.RuleID == "unpinned-action-tag" {
			found = true
			assert.Equal(t, SeverityMedium, f.Severity)
		}
	}
	assert.True(t, found, "Should flag tag-pinned actions from untrusted orgs")
}

func TestWorkflowScanner_TrustedOrgSkipsPinCheck(t *testing.T) {
	diff := `diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- /dev/null
+++ b/.github/workflows/ci.yml
@@ -0,0 +1,8 @@
+name: CI
+on: push
+jobs:
+  build:
+    runs-on: ubuntu-latest
+    steps:
+      - uses: actions/checkout@v4
+      - run: echo hello`

	s := NewWorkflowScanner(false, false, false, true, []string{"actions"})
	result := s.Scan(&ScanContext{
		Diff:         diff,
		ChangedFiles: []string{".github/workflows/ci.yml"},
	})

	for _, f := range result.Findings {
		assert.NotEqual(t, "unpinned-action-tag", f.RuleID, "Should not flag trusted org actions with semver tags")
	}
}

func TestWorkflowScanner_ExcessivePermissions(t *testing.T) {
	diff := `diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- /dev/null
+++ b/.github/workflows/ci.yml
@@ -0,0 +1,8 @@
+name: CI
+on: push
+permissions: write-all
+jobs:
+  build:
+    runs-on: ubuntu-latest
+    steps:
+      - run: echo hello`

	s := NewWorkflowScanner(false, false, true, false, nil)
	result := s.Scan(&ScanContext{
		Diff:         diff,
		ChangedFiles: []string{".github/workflows/ci.yml"},
	})

	found := false
	for _, f := range result.Findings {
		if f.RuleID == "excessive-permissions" {
			found = true
			assert.Equal(t, SeverityHigh, f.Severity)
		}
	}
	assert.True(t, found, "Should detect write-all permissions")
}

func TestWorkflowScanner_SecretsInLogs(t *testing.T) {
	diff := `diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- /dev/null
+++ b/.github/workflows/ci.yml
@@ -0,0 +1,8 @@
+name: CI
+on: push
+jobs:
+  build:
+    runs-on: ubuntu-latest
+    steps:
+      - run: echo ${{ secrets.API_TOKEN }}`

	s := NewWorkflowScanner(false, false, false, false, nil)
	result := s.Scan(&ScanContext{
		Diff:         diff,
		ChangedFiles: []string{".github/workflows/ci.yml"},
	})

	found := false
	for _, f := range result.Findings {
		if f.RuleID == "secrets-in-logs" {
			found = true
			assert.Equal(t, SeverityCritical, f.Severity)
		}
	}
	assert.True(t, found, "Should detect secrets printed to logs")
}

func TestWorkflowScanner_NoWorkflowFiles(t *testing.T) {
	diff := `diff --git a/main.go b/main.go
+++ b/main.go
@@ -1,2 +1,3 @@
 package main
+import "fmt"`

	s := NewWorkflowScanner(true, true, true, true, nil)
	result := s.Scan(&ScanContext{
		Diff:         diff,
		ChangedFiles: []string{"main.go", "go.mod"},
	})

	assert.Len(t, result.Findings, 0)
}

func TestWorkflowScanner_SHAPinnedActionPasses(t *testing.T) {
	diff := `diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- /dev/null
+++ b/.github/workflows/ci.yml
@@ -0,0 +1,8 @@
+name: CI
+on: push
+jobs:
+  build:
+    runs-on: ubuntu-latest
+    steps:
+      - uses: some-org/action@de0fac2e4500dabe0009e67214ff5f5447ce83dd
+      - run: echo hello`

	s := NewWorkflowScanner(false, false, false, true, nil)
	result := s.Scan(&ScanContext{
		Diff:         diff,
		ChangedFiles: []string{".github/workflows/ci.yml"},
	})

	for _, f := range result.Findings {
		assert.NotContains(t, f.RuleID, "unpinned", "SHA-pinned actions should pass")
	}
}

func TestFilterWorkflowFiles(t *testing.T) {
	files := []string{
		".github/workflows/ci.yml",
		".github/workflows/deploy.yaml",
		"src/main.go",
		".github/CODEOWNERS",
	}

	result := filterWorkflowFiles(files)
	require.Len(t, result, 2)
	assert.Contains(t, result, ".github/workflows/ci.yml")
	assert.Contains(t, result, ".github/workflows/deploy.yaml")
}
