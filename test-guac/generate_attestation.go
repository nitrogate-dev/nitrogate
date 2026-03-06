//go:build ignore

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/nitrogate/nitrogate/internal/attest"
	"github.com/nitrogate/nitrogate/internal/gate"
	"github.com/nitrogate/nitrogate/internal/scanner"
)

func main() {
	results := []scanner.ScanResult{
		{
			Scanner: "secrets",
			Findings: []scanner.Finding{
				{Scanner: "secrets", RuleID: "aws-key", Title: "AWS Access Key Detected", Severity: scanner.SeverityCritical, File: "config.ts", Line: 42},
			},
			Duration: "120ms",
		},
		{
			Scanner: "npm-supply-chain",
			Findings: []scanner.Finding{
				{Scanner: "npm-supply-chain", RuleID: "compromised-package", Title: "Compromised Package: event-stream", Severity: scanner.SeverityCritical},
				{Scanner: "npm-supply-chain", RuleID: "npm-cooldown", Title: "New Version: lodash@4.99.0 (2d old)", Severity: scanner.SeverityMedium},
			},
			Duration: "340ms",
		},
		{Scanner: "dependencies", Duration: "200ms"},
	}

	gateResult := gate.Evaluate("gate", scanner.SeverityHigh, results)
	stmt := attest.BuildStatement(gateResult, "myorg/myrepo", 123, "abc123def456", "789012abc345", []string{"package.json", "config.ts"}, "diff content")

	stmtJSON, _ := stmt.ToJSON()

	// DSSE envelope with base64 payload (what GUAC expects)
	payloadB64 := base64.StdEncoding.EncodeToString(stmtJSON)
	envelope := map[string]interface{}{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     payloadB64,
		"signatures": []map[string]string{
			{"keyid": "nitrogate-ed25519", "sig": base64.StdEncoding.EncodeToString([]byte("test-signature"))},
		},
	}
	envJSON, _ := json.MarshalIndent(envelope, "", "  ")
	os.WriteFile("test-guac/attestation.json", envJSON, 0644)

	// Also write an SPDX SBOM for the repo (GUAC ingests SBOMs natively)
	sbom := map[string]interface{}{
		"spdxVersion":    "SPDX-2.3",
		"dataLicense":    "CC0-1.0",
		"SPDXID":         "SPDXRef-DOCUMENT",
		"name":           "myorg/myrepo",
		"documentNamespace": "https://spdx.org/spdxdocs/myorg-myrepo-" + time.Now().Format("20060102"),
		"creationInfo": map[string]interface{}{
			"created":  time.Now().UTC().Format(time.RFC3339),
			"creators": []string{"Tool: nitrogate-1.0.0"},
		},
		"packages": []map[string]interface{}{
			{
				"SPDXID":           "SPDXRef-Package-myrepo",
				"name":             "myorg/myrepo",
				"versionInfo":      "1.0.0",
				"downloadLocation": "https://github.com/myorg/myrepo",
				"supplier":         "Organization: myorg",
			},
		},
	}
	sbomJSON, _ := json.MarshalIndent(sbom, "", "  ")
	os.WriteFile("test-guac/sbom.json", sbomJSON, 0644)

	// Copy SBOM to ingest/ directory (only this file goes to guacone collect)
	os.MkdirAll("test-guac/ingest", 0755)
	os.WriteFile("test-guac/ingest/sbom.json", sbomJSON, 0644)

	fmt.Printf("Generated DSSE envelope + SBOM at %s\n", time.Now().Format(time.RFC3339))
	fmt.Printf("Gate decision: %s, findings: %d\n", gateResult.Decision, gateResult.Summary.TotalFindings)
}
