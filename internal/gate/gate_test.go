package gate

import (
	"testing"

	"github.com/nitrogate/nitrogate/internal/scanner"
	"github.com/stretchr/testify/assert"
)

func TestEvaluate_PassWithNoFindings(t *testing.T) {
	results := []scanner.ScanResult{
		{Scanner: "secrets", Findings: nil, Duration: "5ms"},
		{Scanner: "dependencies", Findings: nil, Duration: "100ms"},
	}

	gate := Evaluate("gate", scanner.SeverityHigh, results)

	assert.Equal(t, DecisionPass, gate.Decision)
	assert.Equal(t, 0, gate.Summary.TotalFindings)
	assert.Equal(t, 2, gate.Summary.ScannersRun)
	assert.Empty(t, gate.Reasons)
}

func TestEvaluate_FailInGateMode(t *testing.T) {
	results := []scanner.ScanResult{
		{
			Scanner: "secrets",
			Findings: []scanner.Finding{
				{Scanner: "secrets", Title: "AWS Key", Severity: scanner.SeverityCritical},
			},
			Duration: "5ms",
		},
	}

	gate := Evaluate("gate", scanner.SeverityHigh, results)

	assert.Equal(t, DecisionFail, gate.Decision)
	assert.Equal(t, 1, gate.Summary.CriticalCount)
	assert.Len(t, gate.Reasons, 1)
}

func TestEvaluate_AdvisoryWithHighFindings(t *testing.T) {
	results := []scanner.ScanResult{
		{
			Scanner: "dependencies",
			Findings: []scanner.Finding{
				{Scanner: "dependencies", Title: "CVE-2021-23337", Severity: scanner.SeverityHigh},
			},
			Duration: "200ms",
		},
	}

	gate := Evaluate("advisory", scanner.SeverityHigh, results)

	assert.Equal(t, DecisionAdvisory, gate.Decision)
	assert.Equal(t, 1, gate.Summary.HighCount)
}

func TestEvaluate_PassWhenBelowThreshold(t *testing.T) {
	results := []scanner.ScanResult{
		{
			Scanner: "licenses",
			Findings: []scanner.Finding{
				{Scanner: "licenses", Title: "LGPL-2.1", Severity: scanner.SeverityMedium},
			},
			Duration: "50ms",
		},
	}

	gate := Evaluate("gate", scanner.SeverityHigh, results)

	assert.Equal(t, DecisionPass, gate.Decision, "Medium finding should not block when threshold is high")
}

func TestEvaluate_MultipleScanners(t *testing.T) {
	results := []scanner.ScanResult{
		{
			Scanner: "secrets",
			Findings: []scanner.Finding{
				{Scanner: "secrets", Title: "AWS Key", Severity: scanner.SeverityCritical},
			},
			Duration: "5ms",
		},
		{
			Scanner:  "dependencies",
			Findings: nil,
			Duration: "100ms",
		},
		{
			Scanner: "workflows",
			Findings: []scanner.Finding{
				{Scanner: "workflows", Title: "Script Injection", Severity: scanner.SeverityCritical},
				{Scanner: "workflows", Title: "Unpinned Action", Severity: scanner.SeverityMedium},
			},
			Duration: "10ms",
		},
	}

	gate := Evaluate("gate", scanner.SeverityHigh, results)

	assert.Equal(t, DecisionFail, gate.Decision)
	assert.Equal(t, 3, gate.Summary.TotalFindings)
	assert.Equal(t, 2, gate.Summary.CriticalCount)
	assert.Equal(t, 1, gate.Summary.MediumCount)
	assert.Equal(t, 3, gate.Summary.ScannersRun)
}

func TestEvaluate_ScannerError(t *testing.T) {
	results := []scanner.ScanResult{
		{Scanner: "dependencies", Error: "OSV API timeout", Duration: "30s"},
	}

	gate := Evaluate("gate", scanner.SeverityHigh, results)

	assert.Equal(t, DecisionPass, gate.Decision)
	assert.Equal(t, 1, gate.Summary.ScannersWithError)
	assert.Contains(t, gate.Reasons[0], "error")
}

func TestFormatSummaryLine(t *testing.T) {
	gate := GateResult{
		Decision: DecisionPass,
		Summary:  GateSummary{ScannersRun: 4},
	}
	line := gate.FormatSummaryLine()
	assert.Contains(t, line, "PASS")
	assert.Contains(t, line, "No issues")

	gate2 := GateResult{
		Decision: DecisionFail,
		Summary: GateSummary{
			CriticalCount: 2,
			HighCount:     1,
			ScannersRun:   4,
		},
	}
	line2 := gate2.FormatSummaryLine()
	assert.Contains(t, line2, "FAIL")
	assert.Contains(t, line2, "2 critical")
	assert.Contains(t, line2, "1 high")
}
