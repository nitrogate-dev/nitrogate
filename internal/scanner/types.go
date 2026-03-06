package scanner

import "fmt"

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

func ParseSeverity(s string) Severity {
	switch s {
	case "info":
		return SeverityInfo
	case "low":
		return SeverityLow
	case "medium":
		return SeverityMedium
	case "high":
		return SeverityHigh
	case "critical":
		return SeverityCritical
	default:
		return SeverityInfo
	}
}

type Finding struct {
	Scanner     string   `json:"scanner"`
	RuleID      string   `json:"ruleId"`
	Title       string   `json:"title"`
	Detail      string   `json:"detail"`
	Severity    Severity `json:"severity"`
	File        string   `json:"file,omitempty"`
	Line        int      `json:"line,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

func (f Finding) SeverityString() string {
	return f.Severity.String()
}

func (f Finding) Summary() string {
	if f.File != "" {
		return fmt.Sprintf("[%s] %s: %s (%s:%d)", f.Severity, f.Scanner, f.Title, f.File, f.Line)
	}
	return fmt.Sprintf("[%s] %s: %s", f.Severity, f.Scanner, f.Title)
}

type ScanResult struct {
	Scanner  string    `json:"scanner"`
	Findings []Finding `json:"findings"`
	Error    string    `json:"error,omitempty"`
	Duration string    `json:"duration"`
}

func (r ScanResult) HasBlocking(threshold Severity) bool {
	for _, f := range r.Findings {
		if f.Severity >= threshold {
			return true
		}
	}
	return false
}

func (r ScanResult) CountBySeverity(sev Severity) int {
	count := 0
	for _, f := range r.Findings {
		if f.Severity == sev {
			count++
		}
	}
	return count
}

type Scanner interface {
	Name() string
	Scan(ctx *ScanContext) ScanResult
}

type ScanContext struct {
	Diff         string
	ChangedFiles []string
	RepoFullName string
	PRNumber     int
	BaseSHA      string
	HeadSHA      string
	RepoRoot     string
}
