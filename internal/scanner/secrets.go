package scanner

import (
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type SecretPattern struct {
	Name     string
	Regex    *regexp.Regexp
	Severity Severity
}

var defaultSecretPatterns = []SecretPattern{
	{
		Name:     "AWS Access Key ID",
		Regex:    regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Severity: SeverityCritical,
	},
	{
		Name:     "AWS Secret Access Key",
		Regex:    regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`),
		Severity: SeverityCritical,
	},
	{
		Name:     "GitHub Personal Access Token",
		Regex:    regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`),
		Severity: SeverityCritical,
	},
	{
		Name:     "GitHub Fine-grained PAT",
		Regex:    regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82}`),
		Severity: SeverityCritical,
	},
	{
		Name:     "Private Key (PEM)",
		Regex:    regexp.MustCompile(`-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)\s+PRIVATE\s+KEY-----`),
		Severity: SeverityCritical,
	},
	{
		Name:     "Google API Key",
		Regex:    regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
		Severity: SeverityCritical,
	},
	{
		Name:     "Slack Token",
		Regex:    regexp.MustCompile(`xox[bpors]-[A-Za-z0-9]{10,}`),
		Severity: SeverityHigh,
	},
	{
		Name:     "Stripe Secret Key",
		Regex:    regexp.MustCompile(`sk_(live|test)_[A-Za-z0-9]{24,}`),
		Severity: SeverityCritical,
	},
	{
		Name:     "Stripe Publishable Key",
		Regex:    regexp.MustCompile(`pk_live_[A-Za-z0-9]{24,}`),
		Severity: SeverityMedium,
	},
	{
		Name:     "JWT Token",
		Regex:    regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
		Severity: SeverityHigh,
	},
	{
		Name:     "Database Connection String",
		Regex:    regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis|amqp)://[^\s'"]{10,}`),
		Severity: SeverityHigh,
	},
	{
		Name:     "Generic API Key Assignment",
		Regex:    regexp.MustCompile(`(?i)(api[_-]?(key|secret|token)|secret[_-]?key)\s*[=:]\s*['"][A-Za-z0-9/+=_-]{16,}['"]`),
		Severity: SeverityMedium,
	},
	{
		Name:     "Heroku API Key",
		Regex:    regexp.MustCompile(`(?i)heroku[_-]?api[_-]?key\s*[=:]\s*[0-9a-f-]{36}`),
		Severity: SeverityHigh,
	},
	{
		Name:     "Twilio Auth Token",
		Regex:    regexp.MustCompile(`(?i)twilio[_-]?auth[_-]?token\s*[=:]\s*[0-9a-f]{32}`),
		Severity: SeverityHigh,
	},
	{
		Name:     "SendGrid API Key",
		Regex:    regexp.MustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`),
		Severity: SeverityHigh,
	},
	{
		Name:     "Mailgun API Key",
		Regex:    regexp.MustCompile(`key-[A-Za-z0-9]{32}`),
		Severity: SeverityHigh,
	},
	{
		Name:     "Azure Storage Key",
		Regex:    regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}`),
		Severity: SeverityCritical,
	},
}

type SecretScanner struct {
	Patterns   []SecretPattern
	AllowFiles []string
	MinEntropy float64
}

func NewSecretScanner(allowFiles []string, customPatterns []SecretPattern) *SecretScanner {
	patterns := make([]SecretPattern, len(defaultSecretPatterns))
	copy(patterns, defaultSecretPatterns)
	patterns = append(patterns, customPatterns...)

	return &SecretScanner{
		Patterns:   patterns,
		AllowFiles: allowFiles,
		MinEntropy: 4.5,
	}
}

func (s *SecretScanner) Name() string { return "secrets" }

func (s *SecretScanner) Scan(ctx *ScanContext) ScanResult {
	start := time.Now()
	var findings []Finding

	lines := strings.Split(ctx.Diff, "\n")
	currentFile := ""
	lineNum := 0

	for _, line := range lines {
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = strings.TrimPrefix(line, "+++ b/")
			lineNum = 0
			continue
		}
		if strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "diff --git") {
			continue
		}
		if strings.HasPrefix(line, "@@") {
			parts := strings.Split(line, "+")
			if len(parts) >= 2 {
				fmt.Sscanf(parts[1], "%d", &lineNum)
			}
			continue
		}

		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			if !strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "\\") {
				lineNum++
			}
			continue
		}

		content := line[1:]
		lineNum++

		if s.isAllowedFile(currentFile) {
			continue
		}

		for _, pattern := range s.Patterns {
			if pattern.Regex.MatchString(content) {
				match := pattern.Regex.FindString(content)
				redacted := redactSecret(match)
				findings = append(findings, Finding{
					Scanner:     "secrets",
					RuleID:      slugify(pattern.Name),
					Title:       pattern.Name,
					Detail:      fmt.Sprintf("Potential %s detected: %s", pattern.Name, redacted),
					Severity:    pattern.Severity,
					File:        currentFile,
					Line:        lineNum,
					Remediation: "Remove the credential and rotate it immediately. Use environment variables or a secrets manager instead.",
					Metadata: map[string]string{
						"pattern": pattern.Name,
						"redacted_match": redacted,
					},
				})
			}
		}

		if s.isHighEntropy(content) && !hasPatternMatch(content, s.Patterns) {
			if isAssignmentContext(content) {
				findings = append(findings, Finding{
					Scanner:     "secrets",
					RuleID:      "high-entropy-string",
					Title:       "High Entropy String",
					Detail:      "Suspicious high-entropy string in assignment context — potential hardcoded secret",
					Severity:    SeverityLow,
					File:        currentFile,
					Line:        lineNum,
					Remediation: "Verify this is not a hardcoded credential. Use environment variables for secrets.",
				})
			}
		}
	}

	return ScanResult{
		Scanner:  "secrets",
		Findings: findings,
		Duration: time.Since(start).String(),
	}
}

func (s *SecretScanner) isAllowedFile(file string) bool {
	for _, pattern := range s.AllowFiles {
		if matchGlob(file, pattern) || matchSuffix(file, pattern) {
			return true
		}
	}
	return false
}

func matchSuffix(file, pattern string) bool {
	if strings.HasPrefix(pattern, "**/*") {
		suffix := strings.TrimPrefix(pattern, "**/*")
		return strings.Contains(file, strings.TrimPrefix(suffix, ".")) && strings.HasSuffix(file, strings.TrimPrefix(suffix, ""))
	}
	return false
}

func (s *SecretScanner) isHighEntropy(line string) bool {
	tokens := extractTokens(line)
	for _, token := range tokens {
		if len(token) >= 16 && shannonEntropy(token) > s.MinEntropy {
			return true
		}
	}
	return false
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func extractTokens(line string) []string {
	re := regexp.MustCompile(`[A-Za-z0-9+/=_-]{16,}`)
	return re.FindAllString(line, -1)
}

func isAssignmentContext(line string) bool {
	assignRe := regexp.MustCompile(`(?i)(=|:|\bset\b|\bexport\b)\s*['"]?[A-Za-z0-9+/=_-]{16,}`)
	return assignRe.MatchString(line)
}

func hasPatternMatch(line string, patterns []SecretPattern) bool {
	for _, p := range patterns {
		if p.Regex.MatchString(line) {
			return true
		}
	}
	return false
}

func redactSecret(secret string) string {
	if len(secret) <= 8 {
		return "****"
	}
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}

func slugify(name string) string {
	s := strings.ToLower(name)
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "(", "")
	s = strings.ReplaceAll(s, ")", "")
	return s
}

func matchGlob(path, pattern string) bool {
	if strings.HasPrefix(pattern, "**/") {
		suffix := strings.TrimPrefix(pattern, "**/")
		if strings.Contains(suffix, "*") {
			suffixRegex := globToRegex(suffix)
			base := filepath.Base(path)
			matched, _ := regexp.MatchString(suffixRegex, base)
			return matched
		}
		return strings.HasSuffix(path, suffix) || strings.Contains(path, suffix)
	}
	if strings.HasPrefix(pattern, "**") {
		suffix := strings.TrimPrefix(pattern, "**")
		return strings.HasSuffix(path, suffix)
	}
	matched, _ := regexp.MatchString(globToRegex(pattern), path)
	return matched
}

func globToRegex(glob string) string {
	s := regexp.QuoteMeta(glob)
	s = strings.ReplaceAll(s, `\*\*`, `.*`)
	s = strings.ReplaceAll(s, `\*`, `[^/]*`)
	s = strings.ReplaceAll(s, `\?`, `.`)
	return "^" + s + "$"
}
