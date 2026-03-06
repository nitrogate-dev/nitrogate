package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/nitrogate/nitrogate/internal/gate"
	"github.com/nitrogate/nitrogate/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKey(t *testing.T) string {
	seed := make([]byte, ed25519.SeedSize)
	_, err := rand.Read(seed)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(seed)
}

func buildTestStatement() *InTotoStatement {
	gateResult := gate.GateResult{
		Decision: gate.DecisionPass,
		Mode:     "gate",
		Summary:  gate.GateSummary{TotalFindings: 0, ScannersRun: 3},
		ScanResults: []scanner.ScanResult{
			{Scanner: "secrets", Findings: nil, Duration: "10ms"},
		},
	}

	return BuildStatement(
		gateResult,
		"org/repo",
		42,
		"base123", "head456",
		[]string{"main.go", "go.mod"},
		"diff content here",
	)
}

func TestSignAndVerify(t *testing.T) {
	key := generateTestKey(t)
	stmt := buildTestStatement()

	signed, err := Sign(stmt, key)
	require.NoError(t, err)
	require.NotNil(t, signed)

	assert.Equal(t, "application/vnd.in-toto+json", signed.Envelope.PayloadType)
	assert.NotEmpty(t, signed.Envelope.Payload)
	assert.Len(t, signed.Envelope.Signatures, 1)
	assert.NotEmpty(t, signed.Envelope.Signatures[0].Sig)
	assert.NotEmpty(t, signed.PublicKey)

	valid, err := Verify(signed)
	require.NoError(t, err)
	assert.True(t, valid, "Signature should be valid")
}

func TestSignAndVerify_TamperDetection(t *testing.T) {
	key := generateTestKey(t)
	stmt := buildTestStatement()

	signed, err := Sign(stmt, key)
	require.NoError(t, err)

	valid, err := Verify(signed)
	require.NoError(t, err)
	assert.True(t, valid)

	payloadBytes, _ := base64.StdEncoding.DecodeString(signed.Envelope.Payload)
	var decoded InTotoStatement
	json.Unmarshal(payloadBytes, &decoded)
	decoded.Predicate.Gate.Decision = "PASS"
	tamperedPayload, _ := json.Marshal(decoded)
	signed.Envelope.Payload = base64.StdEncoding.EncodeToString(tamperedPayload)

	valid, err = Verify(signed)
	require.NoError(t, err)
	assert.False(t, valid, "Tampered attestation should fail verification")
}

func TestSign_InvalidKey(t *testing.T) {
	stmt := buildTestStatement()

	_, err := Sign(stmt, "not-valid-base64!!!")
	assert.Error(t, err)

	shortKey := base64.StdEncoding.EncodeToString([]byte("tooshort"))
	_, err = Sign(stmt, shortKey)
	assert.Error(t, err)
}

func TestExtractStatement(t *testing.T) {
	key := generateTestKey(t)
	stmt := buildTestStatement()

	signed, err := Sign(stmt, key)
	require.NoError(t, err)

	extracted, err := ExtractStatement(signed)
	require.NoError(t, err)
	assert.Equal(t, InTotoStatementType, extracted.Type)
	assert.Equal(t, ReviewPredicateType, extracted.PredicateType)
	assert.Equal(t, "org/repo", extracted.Predicate.Evidence.Repo)
	assert.Equal(t, 42, extracted.Predicate.Evidence.PR)
}

func TestBuildStatement(t *testing.T) {
	gateResult := gate.GateResult{
		Decision: gate.DecisionFail,
		Mode:     "gate",
		Reasons:  []string{"critical vuln found"},
		Summary:  gate.GateSummary{TotalFindings: 1, CriticalCount: 1, ScannersRun: 2},
		ScanResults: []scanner.ScanResult{
			{
				Scanner: "dependencies",
				Findings: []scanner.Finding{
					{
						Scanner:  "dependencies",
						RuleID:   "known-vulnerability",
						Title:    "CVE-2021-23337",
						Severity: scanner.SeverityCritical,
					},
				},
				Duration: "500ms",
			},
		},
	}

	stmt := BuildStatement(gateResult, "myorg/myrepo", 99, "base", "head", []string{"go.sum"}, "diff")

	assert.Equal(t, InTotoStatementType, stmt.Type)
	assert.Equal(t, ReviewPredicateType, stmt.PredicateType)
	assert.Len(t, stmt.Subject, 1)
	assert.Equal(t, "myorg/myrepo", stmt.Subject[0].Name)
	assert.Equal(t, "FAIL", stmt.Predicate.Gate.Decision)
	assert.Equal(t, 1, stmt.Predicate.Gate.Summary.CriticalCount)
	assert.Len(t, stmt.Predicate.Findings, 1)
	assert.Equal(t, "CVE-2021-23337", stmt.Predicate.Findings[0].Title)
}

func TestPaeEncode(t *testing.T) {
	result := paeEncode("application/vnd.in-toto+json", []byte("test payload"))
	assert.Contains(t, string(result), "DSSEv1")
	assert.Contains(t, string(result), "application/vnd.in-toto+json")
	assert.Contains(t, string(result), "test payload")
}
