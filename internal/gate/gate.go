package gate

import (
	"fmt"
	"strings"

	"github.com/nitrogate/nitrogate/internal/scanner"
)

type Decision string

const (
	DecisionPass     Decision = "PASS"
	DecisionFail     Decision = "FAIL"
	DecisionAdvisory Decision = "ADVISORY"
)

type GateResult struct {
	Decision    Decision         `json:"decision"`
	Mode        string           `json:"mode"`
	Reasons     []string         `json:"reasons"`
	Summary     GateSummary      `json:"summary"`
	ScanResults []scanner.ScanResult `json:"scanResults"`
}

type GateSummary struct {
	TotalFindings    int `json:"totalFindings"`
	CriticalCount    int `json:"criticalCount"`
	HighCount        int `json:"highCount"`
	MediumCount      int `json:"mediumCount"`
	LowCount         int `json:"lowCount"`
	InfoCount        int `json:"infoCount"`
	ScannersRun      int `json:"scannersRun"`
	ScannersWithError int `json:"scannersWithError"`
}

func Evaluate(mode string, severityThreshold scanner.Severity, results []scanner.ScanResult) GateResult {
	summary := summarize(results)
	var reasons []string

	hasBlocking := false
	for _, r := range results {
		if r.Error != "" {
			reasons = append(reasons, fmt.Sprintf("Scanner '%s' encountered an error: %s", r.Scanner, r.Error))
		}
		for _, f := range r.Findings {
			if f.Severity >= severityThreshold {
				hasBlocking = true
				reasons = append(reasons, fmt.Sprintf("[%s] %s: %s", f.Severity, f.Scanner, f.Title))
			}
		}
	}

	decision := DecisionPass
	if hasBlocking {
		if mode == "gate" {
			decision = DecisionFail
		} else {
			decision = DecisionAdvisory
		}
	}

	return GateResult{
		Decision:    decision,
		Mode:        mode,
		Reasons:     reasons,
		Summary:     summary,
		ScanResults: results,
	}
}

func summarize(results []scanner.ScanResult) GateSummary {
	s := GateSummary{
		ScannersRun: len(results),
	}

	for _, r := range results {
		if r.Error != "" {
			s.ScannersWithError++
		}
		for _, f := range r.Findings {
			s.TotalFindings++
			switch f.Severity {
			case scanner.SeverityCritical:
				s.CriticalCount++
			case scanner.SeverityHigh:
				s.HighCount++
			case scanner.SeverityMedium:
				s.MediumCount++
			case scanner.SeverityLow:
				s.LowCount++
			case scanner.SeverityInfo:
				s.InfoCount++
			}
		}
	}

	return s
}

func (g GateResult) FormatSummaryLine() string {
	icon := "✅"
	if g.Decision == DecisionFail {
		icon = "❌"
	} else if g.Decision == DecisionAdvisory {
		icon = "⚠️"
	}

	parts := []string{}
	if g.Summary.CriticalCount > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", g.Summary.CriticalCount))
	}
	if g.Summary.HighCount > 0 {
		parts = append(parts, fmt.Sprintf("%d high", g.Summary.HighCount))
	}
	if g.Summary.MediumCount > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", g.Summary.MediumCount))
	}
	if g.Summary.LowCount > 0 {
		parts = append(parts, fmt.Sprintf("%d low", g.Summary.LowCount))
	}

	if len(parts) == 0 {
		return fmt.Sprintf("%s Quality Gate: **%s** — No issues found across %d scanners", icon, g.Decision, g.Summary.ScannersRun)
	}

	return fmt.Sprintf("%s Quality Gate: **%s** — %s (%d scanners)", icon, g.Decision, strings.Join(parts, ", "), g.Summary.ScannersRun)
}
