package scanner

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretScanner_AWSAccessKey(t *testing.T) {
	diff := `diff --git a/config.ts b/config.ts
--- a/config.ts
+++ b/config.ts
@@ -1,3 +1,4 @@
 const config = {
+  awsKey: "AKIAIOSFODNN7EXAMPLE",
   region: "us-east-1"
 };`

	s := NewSecretScanner(nil, nil)
	result := s.Scan(&ScanContext{Diff: diff, ChangedFiles: []string{"config.ts"}})

	require.Len(t, result.Findings, 1)
	assert.Equal(t, "secrets", result.Findings[0].Scanner)
	assert.Equal(t, SeverityCritical, result.Findings[0].Severity)
	assert.Contains(t, result.Findings[0].Title, "AWS Access Key")
	assert.Contains(t, result.Findings[0].Detail, "AKIA")
	assert.NotContains(t, result.Findings[0].Detail, "AKIAIOSFODNN7EXAMPLE")
}

func TestSecretScanner_GitHubPAT(t *testing.T) {
	diff := `diff --git a/auth.go b/auth.go
--- a/auth.go
+++ b/auth.go
@@ -1,2 +1,3 @@
 package auth
+var token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"`

	s := NewSecretScanner(nil, nil)
	result := s.Scan(&ScanContext{Diff: diff, ChangedFiles: []string{"auth.go"}})

	require.Len(t, result.Findings, 1)
	assert.Equal(t, SeverityCritical, result.Findings[0].Severity)
	assert.Contains(t, result.Findings[0].Title, "GitHub Personal Access Token")
}

func TestSecretScanner_PrivateKey(t *testing.T) {
	diff := `diff --git a/key.pem b/key.pem
--- /dev/null
+++ b/key.pem
@@ -0,0 +1,3 @@
+-----BEGIN RSA PRIVATE KEY-----
+MIIEowIBAAKCAQEA2Z3qX2BTLS4e
+-----END RSA PRIVATE KEY-----`

	s := NewSecretScanner(nil, nil)
	result := s.Scan(&ScanContext{Diff: diff, ChangedFiles: []string{"key.pem"}})

	require.Len(t, result.Findings, 1)
	assert.Equal(t, SeverityCritical, result.Findings[0].Severity)
	assert.Contains(t, result.Findings[0].Title, "Private Key")
}

func TestSecretScanner_JWT(t *testing.T) {
	diff := `diff --git a/test.js b/test.js
--- a/test.js
+++ b/test.js
@@ -1,2 +1,3 @@
 const api = require('./api');
+const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";`

	s := NewSecretScanner(nil, nil)
	result := s.Scan(&ScanContext{Diff: diff, ChangedFiles: []string{"test.js"}})

	require.Len(t, result.Findings, 1)
	assert.Equal(t, SeverityHigh, result.Findings[0].Severity)
	assert.Contains(t, result.Findings[0].Title, "JWT")
}

func TestSecretScanner_DatabaseConnectionString(t *testing.T) {
	diff := `diff --git a/db.py b/db.py
--- a/db.py
+++ b/db.py
@@ -1,2 +1,3 @@
 import psycopg2
+DB_URL = "postgres://admin:secret123@db.example.com:5432/production"`

	s := NewSecretScanner(nil, nil)
	result := s.Scan(&ScanContext{Diff: diff, ChangedFiles: []string{"db.py"}})

	require.Len(t, result.Findings, 1)
	assert.Equal(t, SeverityHigh, result.Findings[0].Severity)
	assert.Contains(t, result.Findings[0].Title, "Database Connection String")
}

func TestSecretScanner_StripeKey(t *testing.T) {
	stripeKey := "sk_" + "test_4eC39HqLyjWDarjtT1zdp7dc"
	diff := fmt.Sprintf(`diff --git a/payment.ts b/payment.ts
--- a/payment.ts
+++ b/payment.ts
@@ -1,2 +1,3 @@
 import Stripe from 'stripe';
+const stripe = new Stripe("%s");`, stripeKey)

	s := NewSecretScanner(nil, nil)
	result := s.Scan(&ScanContext{Diff: diff, ChangedFiles: []string{"payment.ts"}})

	require.Len(t, result.Findings, 1)
	assert.Equal(t, SeverityCritical, result.Findings[0].Severity)
	assert.Contains(t, result.Findings[0].Title, "Stripe Secret Key")
}

func TestSecretScanner_MultipleSecrets(t *testing.T) {
	stripeKey := "sk_" + "test_4eC39HqLyjWDarjtT1zdp7dc"
	diff := fmt.Sprintf(`diff --git a/config.env b/config.env
--- /dev/null
+++ b/config.env
@@ -0,0 +1,4 @@
+AWS_KEY=AKIAIOSFODNN7EXAMPLE
+STRIPE_KEY=%s
+DB_URL=postgres://admin:pass@localhost:5432/db
+SLACK_TOKEN=xoxb-FAKE0TOKEN0FOR0TESTING`, stripeKey)

	s := NewSecretScanner(nil, nil)
	result := s.Scan(&ScanContext{Diff: diff, ChangedFiles: []string{"config.env"}})

	assert.GreaterOrEqual(t, len(result.Findings), 4)
	for _, f := range result.Findings {
		assert.Equal(t, "secrets", f.Scanner)
		assert.True(t, f.Severity >= SeverityHigh)
	}
}

func TestSecretScanner_AllowFiles(t *testing.T) {
	diff := `diff --git a/auth.test.ts b/auth.test.ts
--- a/auth.test.ts
+++ b/auth.test.ts
@@ -1,2 +1,3 @@
 describe('auth', () => {
+  const testToken = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";`

	s := NewSecretScanner([]string{"**/*.test.ts"}, nil)
	result := s.Scan(&ScanContext{Diff: diff, ChangedFiles: []string{"auth.test.ts"}})

	assert.Len(t, result.Findings, 0, "Should skip allowed test files")
}

func TestSecretScanner_NoFalsePositivesOnRemovedLines(t *testing.T) {
	diff := `diff --git a/config.ts b/config.ts
--- a/config.ts
+++ b/config.ts
@@ -1,3 +1,2 @@
 const config = {
-  awsKey: "AKIAIOSFODNN7EXAMPLE",
   region: "us-east-1"
 };`

	s := NewSecretScanner(nil, nil)
	result := s.Scan(&ScanContext{Diff: diff, ChangedFiles: []string{"config.ts"}})

	assert.Len(t, result.Findings, 0, "Should not flag removed lines")
}

func TestSecretScanner_CustomPatterns(t *testing.T) {
	custom := []SecretPattern{
		{
			Name:     "Internal Token",
			Regex:    mustCompile(`MYORG_[A-Z0-9]{32}`),
			Severity: SeverityCritical,
		},
	}

	diff := `diff --git a/app.go b/app.go
--- a/app.go
+++ b/app.go
@@ -1,2 +1,3 @@
 package main
+var token = "MYORG_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"`

	s := NewSecretScanner(nil, custom)
	result := s.Scan(&ScanContext{Diff: diff, ChangedFiles: []string{"app.go"}})

	require.GreaterOrEqual(t, len(result.Findings), 1)
	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Title, "Internal Token") {
			found = true
		}
	}
	assert.True(t, found, "Should detect custom pattern 'Internal Token'")
}

func TestSecretScanner_NoDiff(t *testing.T) {
	s := NewSecretScanner(nil, nil)
	result := s.Scan(&ScanContext{Diff: "", ChangedFiles: nil})
	assert.Len(t, result.Findings, 0)
}

func TestRedactSecret(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"AKIAIOSFODNN7EXAMPLE", "AKIA************MPLE"},
		{"short", "****"},
		{"12345678", "****"},
		{"abcdefghijklmnop", "abcd********mnop"},
	}

	for _, tt := range tests {
		result := redactSecret(tt.input)
		assert.Equal(t, tt.expected, result)
	}
}

func TestShannonEntropy(t *testing.T) {
	low := shannonEntropy("aaaaaaaaaa")
	high := shannonEntropy("aB3$fG9!kL2@mN5#")

	assert.Less(t, low, 2.0)
	assert.Greater(t, high, 3.5)
}

func TestSecretScanner_SlackToken(t *testing.T) {
	diff := `diff --git a/notify.js b/notify.js
--- a/notify.js
+++ b/notify.js
@@ -1,2 +1,3 @@
 const slack = require('slack');
+const SLACK_BOT_TOKEN = "xoxb-FAKE0TOKEN0FOR0TESTING0ONLY";`

	s := NewSecretScanner(nil, nil)
	result := s.Scan(&ScanContext{Diff: diff, ChangedFiles: []string{"notify.js"}})

	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Title, "Slack") {
			found = true
			assert.Equal(t, SeverityHigh, f.Severity)
		}
	}
	assert.True(t, found, "Should detect Slack token")
}

func TestSecretScanner_GenericAPIKey(t *testing.T) {
	diff := `diff --git a/config.py b/config.py
--- a/config.py
+++ b/config.py
@@ -1,2 +1,3 @@
 import os
+API_KEY = "sk_prod_abcdefghijklmnopqrstuvwxyz123456"`

	s := NewSecretScanner(nil, nil)
	result := s.Scan(&ScanContext{Diff: diff, ChangedFiles: []string{"config.py"}})

	assert.Greater(t, len(result.Findings), 0, "Should detect generic API key pattern")
}

func mustCompile(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}
