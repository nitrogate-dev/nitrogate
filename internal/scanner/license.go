package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type LicenseCategory int

const (
	LicensePermissive LicenseCategory = iota
	LicenseWeakCopyleft
	LicenseStrongCopyleft
	LicenseNetworkCopyleft
	LicenseUnknown
)

func (c LicenseCategory) String() string {
	switch c {
	case LicensePermissive:
		return "permissive"
	case LicenseWeakCopyleft:
		return "weak-copyleft"
	case LicenseStrongCopyleft:
		return "strong-copyleft"
	case LicenseNetworkCopyleft:
		return "network-copyleft"
	default:
		return "unknown"
	}
}

var licenseClassification = map[string]LicenseCategory{
	"MIT":            LicensePermissive,
	"Apache-2.0":     LicensePermissive,
	"BSD-2-Clause":   LicensePermissive,
	"BSD-3-Clause":   LicensePermissive,
	"ISC":            LicensePermissive,
	"0BSD":           LicensePermissive,
	"Unlicense":      LicensePermissive,
	"CC0-1.0":        LicensePermissive,
	"Zlib":           LicensePermissive,
	"PSF-2.0":        LicensePermissive,
	"Python-2.0":     LicensePermissive,
	"BSL-1.0":        LicensePermissive,
	"WTFPL":          LicensePermissive,
	"BlueOak-1.0.0":  LicensePermissive,

	"LGPL-2.0":      LicenseWeakCopyleft,
	"LGPL-2.1":      LicenseWeakCopyleft,
	"LGPL-3.0":      LicenseWeakCopyleft,
	"MPL-2.0":       LicenseWeakCopyleft,
	"EPL-1.0":       LicenseWeakCopyleft,
	"EPL-2.0":       LicenseWeakCopyleft,
	"CDDL-1.0":      LicenseWeakCopyleft,
	"CPL-1.0":       LicenseWeakCopyleft,

	"GPL-2.0":       LicenseStrongCopyleft,
	"GPL-2.0-only":  LicenseStrongCopyleft,
	"GPL-2.0-or-later": LicenseStrongCopyleft,
	"GPL-3.0":       LicenseStrongCopyleft,
	"GPL-3.0-only":  LicenseStrongCopyleft,
	"GPL-3.0-or-later": LicenseStrongCopyleft,
	"EUPL-1.1":      LicenseStrongCopyleft,
	"EUPL-1.2":      LicenseStrongCopyleft,

	"AGPL-3.0":       LicenseNetworkCopyleft,
	"AGPL-3.0-only":  LicenseNetworkCopyleft,
	"AGPL-3.0-or-later": LicenseNetworkCopyleft,
	"SSPL-1.0":       LicenseNetworkCopyleft,
}

type LicenseScanner struct {
	DeniedLicenses  []string
	WarnLicenses    []string
	AllowUnknown    bool
	HTTPClient      *http.Client
}

func NewLicenseScanner(denied, warn []string, allowUnknown bool) *LicenseScanner {
	return &LicenseScanner{
		DeniedLicenses:  denied,
		WarnLicenses:    warn,
		AllowUnknown:    allowUnknown,
		HTTPClient:      &http.Client{Timeout: 15 * time.Second},
	}
}

func (l *LicenseScanner) Name() string { return "licenses" }

func (l *LicenseScanner) Scan(ctx *ScanContext) ScanResult {
	start := time.Now()
	var findings []Finding

	deps := l.extractNewDeps(ctx.Diff, ctx.ChangedFiles)
	if len(deps) == 0 {
		return ScanResult{
			Scanner:  "licenses",
			Findings: nil,
			Duration: time.Since(start).String(),
		}
	}

	for _, dep := range deps {
		license := l.resolveLicense(dep)
		if license == "" {
			license = "UNKNOWN"
		}

		category := classifyLicense(license)
		severity := l.evaluateLicensePolicy(license, category)

		if severity > SeverityInfo {
			findings = append(findings, Finding{
				Scanner:     "licenses",
				RuleID:      "license-" + strings.ToLower(category.String()),
				Title:       fmt.Sprintf("License: %s (%s)", license, category),
				Detail:      fmt.Sprintf("Dependency %s@%s uses license %s (%s)", dep.Name, dep.Version, license, category),
				Severity:    severity,
				Remediation: l.remediationFor(category),
				Metadata: map[string]string{
					"package":  dep.Name,
					"version":  dep.Version,
					"license":  license,
					"category": category.String(),
				},
			})
		}
	}

	return ScanResult{
		Scanner:  "licenses",
		Findings: findings,
		Duration: time.Since(start).String(),
	}
}

func (l *LicenseScanner) extractNewDeps(diff string, changedFiles []string) []Dependency {
	ds := &DepsScanner{}
	return ds.extractDepsFromDiff(diff, changedFiles)
}

func (l *LicenseScanner) resolveLicense(dep Dependency) string {
	switch dep.Ecosystem {
	case "npm":
		return l.resolveNPMLicense(dep.Name, dep.Version)
	case "PyPI":
		return l.resolvePyPILicense(dep.Name, dep.Version)
	default:
		return ""
	}
}

func (l *LicenseScanner) resolveNPMLicense(name, version string) string {
	url := fmt.Sprintf("https://registry.npmjs.org/%s/%s", name, version)
	resp, err := l.HTTPClient.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()

	var result struct {
		License interface{} `json:"license"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}

	switch v := result.License.(type) {
	case string:
		return v
	case map[string]interface{}:
		if t, ok := v["type"].(string); ok {
			return t
		}
	}
	return ""
}

func (l *LicenseScanner) resolvePyPILicense(name, version string) string {
	url := fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", name, version)
	resp, err := l.HTTPClient.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()

	var result struct {
		Info struct {
			License string `json:"license"`
		} `json:"info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}

	return result.Info.License
}

func classifyLicense(license string) LicenseCategory {
	normalized := strings.TrimSpace(license)
	if cat, ok := licenseClassification[normalized]; ok {
		return cat
	}

	upper := strings.ToUpper(normalized)
	if strings.Contains(upper, "AGPL") {
		return LicenseNetworkCopyleft
	}
	if strings.Contains(upper, "GPL") && !strings.Contains(upper, "LGPL") {
		return LicenseStrongCopyleft
	}
	if strings.Contains(upper, "LGPL") {
		return LicenseWeakCopyleft
	}
	if strings.Contains(upper, "MIT") || strings.Contains(upper, "APACHE") || strings.Contains(upper, "BSD") {
		return LicensePermissive
	}

	return LicenseUnknown
}

func (l *LicenseScanner) evaluateLicensePolicy(license string, category LicenseCategory) Severity {
	for _, denied := range l.DeniedLicenses {
		if strings.EqualFold(denied, license) {
			return SeverityHigh
		}
	}

	if category == LicenseNetworkCopyleft {
		return SeverityHigh
	}
	if category == LicenseStrongCopyleft {
		return SeverityHigh
	}

	for _, warn := range l.WarnLicenses {
		if strings.EqualFold(warn, license) {
			return SeverityMedium
		}
	}
	if category == LicenseWeakCopyleft {
		return SeverityMedium
	}

	if category == LicenseUnknown && !l.AllowUnknown {
		return SeverityMedium
	}

	return SeverityInfo
}

func (l *LicenseScanner) remediationFor(category LicenseCategory) string {
	switch category {
	case LicenseNetworkCopyleft:
		return "AGPL/SSPL requires releasing source code of network services. Replace with a permissively-licensed alternative."
	case LicenseStrongCopyleft:
		return "GPL requires derivative works to be GPL-licensed. Evaluate if this is acceptable or find a permissive alternative."
	case LicenseWeakCopyleft:
		return "LGPL/MPL allows linking but modifications must be shared. Usually acceptable for library use."
	case LicenseUnknown:
		return "License could not be determined. Manually verify the package license before using in production."
	default:
		return ""
	}
}
