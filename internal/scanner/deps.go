package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Dependency struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	Depth     int    `json:"depth"`
	IsNew     bool   `json:"isNew"`
}

type OSVQuery struct {
	Package  OSVPackage `json:"package"`
	Version  string     `json:"version"`
}

type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type OSVBatchRequest struct {
	Queries []OSVQuery `json:"queries"`
}

type OSVBatchResponse struct {
	Results []OSVResult `json:"results"`
}

type OSVResult struct {
	Vulns []OSVVulnerability `json:"vulns"`
}

type OSVVulnerability struct {
	ID       string     `json:"id"`
	Summary  string     `json:"summary"`
	Severity []OSVSeverity `json:"severity"`
	Aliases  []string   `json:"aliases"`
}

type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type DepsScanner struct {
	IgnoreVulns       []string
	SeverityThreshold string
	HTTPClient        *http.Client
}

func NewDepsScanner(ignoreVulns []string, severityThreshold string) *DepsScanner {
	return &DepsScanner{
		IgnoreVulns:       ignoreVulns,
		SeverityThreshold: severityThreshold,
		HTTPClient:        &http.Client{Timeout: 30 * time.Second},
	}
}

func (d *DepsScanner) Name() string { return "dependencies" }

func (d *DepsScanner) Scan(ctx *ScanContext) ScanResult {
	start := time.Now()
	var findings []Finding

	deps := d.extractDepsFromDiff(ctx.Diff, ctx.ChangedFiles)
	if len(deps) == 0 {
		return ScanResult{
			Scanner:  "dependencies",
			Findings: nil,
			Duration: time.Since(start).String(),
		}
	}

	vulnFindings := d.queryOSV(deps)
	findings = append(findings, vulnFindings...)

	for _, dep := range deps {
		if dep.IsNew {
			findings = append(findings, Finding{
				Scanner:  "dependencies",
				RuleID:   "new-dependency",
				Title:    "New Dependency Added",
				Detail:   fmt.Sprintf("New dependency: %s@%s (%s)", dep.Name, dep.Version, dep.Ecosystem),
				Severity: SeverityInfo,
				Metadata: map[string]string{
					"package":   dep.Name,
					"version":   dep.Version,
					"ecosystem": dep.Ecosystem,
				},
			})
		}
	}

	return ScanResult{
		Scanner:  "dependencies",
		Findings: findings,
		Duration: time.Since(start).String(),
	}
}

func (d *DepsScanner) extractDepsFromDiff(diff string, changedFiles []string) []Dependency {
	var deps []Dependency

	for _, file := range changedFiles {
		switch {
		case strings.HasSuffix(file, "package-lock.json"):
			deps = append(deps, d.parseNPMLockFromDiff(diff)...)
		case strings.HasSuffix(file, "go.sum"):
			deps = append(deps, d.parseGoSumFromDiff(diff)...)
		case strings.HasSuffix(file, "requirements.txt"):
			deps = append(deps, d.parseRequirementsFromDiff(diff)...)
		case strings.HasSuffix(file, "Cargo.lock"):
			deps = append(deps, d.parseCargoLockFromDiff(diff)...)
		case strings.HasSuffix(file, "Gemfile.lock"):
			deps = append(deps, d.parseGemfileLockFromDiff(diff)...)
		}
	}

	return deps
}

func (d *DepsScanner) parseNPMLockFromDiff(diff string) []Dependency {
	var deps []Dependency
	lines := strings.Split(diff, "\n")

	inAddedBlock := false
	var currentPkg string

	for _, line := range lines {
		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			inAddedBlock = false
			continue
		}
		content := strings.TrimSpace(line[1:])

		if strings.Contains(content, "\"node_modules/") {
			parts := strings.Split(content, "\"node_modules/")
			if len(parts) >= 2 {
				pkg := strings.Trim(parts[1], `":{ `)
				currentPkg = pkg
				inAddedBlock = true
			}
		}

		if inAddedBlock && strings.Contains(content, `"version"`) {
			parts := strings.Split(content, `"`)
			for i, p := range parts {
				if p == "version" && i+2 < len(parts) {
					version := parts[i+2]
					if currentPkg != "" && version != "" {
						deps = append(deps, Dependency{
							Name:      currentPkg,
							Version:   version,
							Ecosystem: "npm",
							IsNew:     true,
						})
					}
				}
			}
		}
	}

	return deps
}

func (d *DepsScanner) parseGoSumFromDiff(diff string) []Dependency {
	var deps []Dependency
	lines := strings.Split(diff, "\n")

	for _, line := range lines {
		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			continue
		}
		content := strings.TrimSpace(line[1:])
		parts := strings.Fields(content)
		if len(parts) >= 2 {
			name := parts[0]
			version := strings.TrimSuffix(parts[1], "/go.mod")
			version = strings.TrimPrefix(version, "v")
			if name != "" && version != "" && !strings.Contains(name, "//") {
				deps = append(deps, Dependency{
					Name:      name,
					Version:   version,
					Ecosystem: "Go",
					IsNew:     true,
				})
			}
		}
	}

	return deduplicateDeps(deps)
}

func (d *DepsScanner) parseRequirementsFromDiff(diff string) []Dependency {
	var deps []Dependency
	lines := strings.Split(diff, "\n")

	for _, line := range lines {
		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			continue
		}
		content := strings.TrimSpace(line[1:])
		if content == "" || strings.HasPrefix(content, "#") {
			continue
		}

		parts := strings.SplitN(content, "==", 2)
		if len(parts) == 2 {
			deps = append(deps, Dependency{
				Name:      strings.TrimSpace(parts[0]),
				Version:   strings.TrimSpace(parts[1]),
				Ecosystem: "PyPI",
				IsNew:     true,
			})
		}
	}

	return deps
}

func (d *DepsScanner) parseCargoLockFromDiff(diff string) []Dependency {
	var deps []Dependency
	lines := strings.Split(diff, "\n")

	var name, version string
	for _, line := range lines {
		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			continue
		}
		content := strings.TrimSpace(line[1:])

		if strings.HasPrefix(content, "name = ") {
			name = strings.Trim(strings.TrimPrefix(content, "name = "), `"`)
		}
		if strings.HasPrefix(content, "version = ") {
			version = strings.Trim(strings.TrimPrefix(content, "version = "), `"`)
			if name != "" {
				deps = append(deps, Dependency{
					Name:      name,
					Version:   version,
					Ecosystem: "crates.io",
					IsNew:     true,
				})
				name = ""
				version = ""
			}
		}
	}

	return deps
}

func (d *DepsScanner) parseGemfileLockFromDiff(diff string) []Dependency {
	var deps []Dependency
	lines := strings.Split(diff, "\n")

	for _, line := range lines {
		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			continue
		}
		content := strings.TrimSpace(line[1:])

		if strings.Contains(content, "(") && strings.Contains(content, ")") {
			parts := strings.SplitN(content, "(", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				version := strings.TrimSuffix(strings.TrimSpace(parts[1]), ")")
				if name != "" && version != "" {
					deps = append(deps, Dependency{
						Name:      name,
						Version:   version,
						Ecosystem: "RubyGems",
						IsNew:     true,
					})
				}
			}
		}
	}

	return deps
}

func (d *DepsScanner) queryOSV(deps []Dependency) []Finding {
	var findings []Finding

	queries := make([]OSVQuery, 0, len(deps))
	for _, dep := range deps {
		queries = append(queries, OSVQuery{
			Package: OSVPackage{Name: dep.Name, Ecosystem: dep.Ecosystem},
			Version: dep.Version,
		})
	}

	batchSize := 100
	for i := 0; i < len(queries); i += batchSize {
		end := i + batchSize
		if end > len(queries) {
			end = len(queries)
		}
		batch := queries[i:end]

		body, err := json.Marshal(OSVBatchRequest{Queries: batch})
		if err != nil {
			continue
		}

		resp, err := d.HTTPClient.Post("https://api.osv.dev/v1/querybatch", "application/json", bytes.NewReader(body))
		if err != nil {
			findings = append(findings, Finding{
				Scanner:  "dependencies",
				RuleID:   "osv-api-error",
				Title:    "OSV API Error",
				Detail:   fmt.Sprintf("Failed to query OSV.dev: %s", err.Error()),
				Severity: SeverityInfo,
			})
			continue
		}
		defer resp.Body.Close()

		var result OSVBatchResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			continue
		}

		for j, r := range result.Results {
			depIdx := i + j
			if depIdx >= len(deps) {
				break
			}
			dep := deps[depIdx]

			for _, vuln := range r.Vulns {
				if d.isIgnored(vuln.ID) {
					continue
				}

				severity := classifyVulnSeverity(vuln)
				cveID := vuln.ID
				for _, alias := range vuln.Aliases {
					if strings.HasPrefix(alias, "CVE-") {
						cveID = alias
						break
					}
				}

				findings = append(findings, Finding{
					Scanner:     "dependencies",
					RuleID:      "known-vulnerability",
					Title:       fmt.Sprintf("Vulnerable Dependency: %s", cveID),
					Detail:      fmt.Sprintf("%s@%s has %s: %s", dep.Name, dep.Version, cveID, truncate(vuln.Summary, 120)),
					Severity:    severity,
					Remediation: fmt.Sprintf("Upgrade %s to a non-vulnerable version", dep.Name),
					Metadata: map[string]string{
						"package":   dep.Name,
						"version":   dep.Version,
						"vuln_id":   vuln.ID,
						"cve":       cveID,
						"ecosystem": dep.Ecosystem,
					},
				})
			}
		}
	}

	return findings
}

func (d *DepsScanner) isIgnored(vulnID string) bool {
	for _, ignored := range d.IgnoreVulns {
		if ignored == vulnID {
			return true
		}
	}
	return false
}

func classifyVulnSeverity(vuln OSVVulnerability) Severity {
	for _, sev := range vuln.Severity {
		if sev.Type == "CVSS_V3" {
			score := parseCVSSScore(sev.Score)
			switch {
			case score >= 9.0:
				return SeverityCritical
			case score >= 7.0:
				return SeverityHigh
			case score >= 4.0:
				return SeverityMedium
			default:
				return SeverityLow
			}
		}
	}
	return SeverityMedium
}

func parseCVSSScore(vector string) float64 {
	var score float64
	fmt.Sscanf(vector, "%f", &score)
	return score
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func deduplicateDeps(deps []Dependency) []Dependency {
	seen := make(map[string]bool)
	var result []Dependency
	for _, dep := range deps {
		key := dep.Name + "@" + dep.Version
		if !seen[key] {
			seen[key] = true
			result = append(result, dep)
		}
	}
	return result
}
