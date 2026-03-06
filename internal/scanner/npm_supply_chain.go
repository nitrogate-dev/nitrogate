package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var popularPackages = []string{
	"express", "react", "lodash", "axios", "webpack", "babel",
	"typescript", "eslint", "prettier", "jest", "mocha", "chai",
	"next", "vue", "angular", "svelte", "tailwindcss", "postcss",
	"moment", "dayjs", "commander", "yargs", "chalk", "inquirer",
	"dotenv", "cors", "helmet", "morgan", "passport", "jsonwebtoken",
	"mongoose", "sequelize", "prisma", "knex", "pg", "mysql2",
	"redis", "ioredis", "socket.io", "ws", "nodemailer",
	"sharp", "multer", "formidable", "uuid", "nanoid",
	"zod", "joi", "yup", "ajv", "class-validator",
	"rxjs", "ramda", "underscore", "immutable", "immer",
	"puppeteer", "playwright", "cypress", "selenium-webdriver",
	"fastify", "koa", "hapi", "restify", "nestjs",
	"npm", "yarn", "pnpm", "turbo", "lerna", "nx",
}

var knownCompromisedPackages = map[string]string{
	"event-stream":   "Hijacked via flatmap-stream — cryptocurrency wallet theft (2018)",
	"ua-parser-js":   "Hijacked v0.7.29/0.8.0/1.0.0 — cryptominer + password stealer",
	"coa":            "Hijacked v2.0.3-3.1.3 — malware dropper",
	"rc":             "Hijacked v1.2.9/1.3.9/2.3.9 — malware dropper",
	"colors":         "Sabotaged v1.4.1-1.4.2 — infinite loop protestware",
	"faker":          "Sabotaged v6.6.6 — infinite loop protestware",
	"node-ipc":       "Sabotaged v10.1.1-11.0.0 — wiper targeting Russia/Belarus IPs",
	"peacenotwar":    "Malware distributed via node-ipc",
	"flatmap-stream":  "Malicious payload targeting cryptocurrency wallets",
	"eslint-scope":   "Hijacked v3.7.2 — npm token theft",
	"getcookies":     "Backdoor — HTTP header-triggered RCE",
	"crossenv":       "Typosquat of cross-env — credential theft",
	"babelcli":       "Typosquat of babel-cli — credential theft",
	"mongose":        "Typosquat of mongoose — credential theft",
	"mariadb":        "Compromised v3.4.1 — malware payload",
	"lottie-player":  "Compromised — cryptocurrency wallet drainer",
}

type npmRegistryResponse struct {
	Name     string                    `json:"name"`
	Time     map[string]string         `json:"time"`
	Versions map[string]json.RawMessage `json:"versions"`
}

type npmVersionScripts struct {
	Scripts map[string]string `json:"scripts"`
}

type NPMSupplyChainScanner struct {
	CooldownDays        int
	CheckCompromised    bool
	CheckTyposquatting  bool
	CheckInstallScripts bool
	HTTPClient          *http.Client
}

func NewNPMSupplyChainScanner(cooldownDays int, checkCompromised, checkTyposquatting, checkInstallScripts bool) *NPMSupplyChainScanner {
	return &NPMSupplyChainScanner{
		CooldownDays:        cooldownDays,
		CheckCompromised:    checkCompromised,
		CheckTyposquatting:  checkTyposquatting,
		CheckInstallScripts: checkInstallScripts,
		HTTPClient:          &http.Client{Timeout: 15 * time.Second},
	}
}

func (n *NPMSupplyChainScanner) Name() string { return "npm-supply-chain" }

func (n *NPMSupplyChainScanner) Scan(ctx *ScanContext) ScanResult {
	start := time.Now()
	var findings []Finding

	deps := n.extractNPMDeps(ctx.Diff, ctx.ChangedFiles)
	if len(deps) == 0 {
		return ScanResult{Scanner: n.Name(), Duration: time.Since(start).String()}
	}

	for _, dep := range deps {
		if n.CheckCompromised {
			findings = append(findings, n.checkCompromised(dep)...)
		}
		if n.CheckTyposquatting {
			findings = append(findings, n.checkTyposquat(dep)...)
		}

		if n.CooldownDays > 0 || n.CheckInstallScripts {
			findings = append(findings, n.checkRegistry(dep)...)
		}
	}

	return ScanResult{
		Scanner:  n.Name(),
		Findings: findings,
		Duration: time.Since(start).String(),
	}
}

func (n *NPMSupplyChainScanner) extractNPMDeps(diff string, changedFiles []string) []Dependency {
	hasNPMFile := false
	for _, f := range changedFiles {
		if strings.HasSuffix(f, "package-lock.json") || strings.HasSuffix(f, "package.json") || strings.HasSuffix(f, "yarn.lock") {
			hasNPMFile = true
			break
		}
	}
	if !hasNPMFile {
		return nil
	}

	var deps []Dependency
	lines := strings.Split(diff, "\n")
	var currentPkg string
	inAddedBlock := false

	for _, line := range lines {
		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			inAddedBlock = false
			continue
		}
		content := strings.TrimSpace(line[1:])

		if strings.Contains(content, `"node_modules/`) {
			parts := strings.Split(content, `"node_modules/`)
			if len(parts) >= 2 {
				currentPkg = strings.Trim(parts[1], `":{ `)
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
							Name: currentPkg, Version: version,
							Ecosystem: "npm", IsNew: true,
						})
					}
				}
			}
		}
	}

	return deduplicateDeps(deps)
}

func (n *NPMSupplyChainScanner) checkCompromised(dep Dependency) []Finding {
	reason, ok := knownCompromisedPackages[dep.Name]
	if !ok {
		return nil
	}
	return []Finding{{
		Scanner:     n.Name(),
		RuleID:      "compromised-package",
		Title:       fmt.Sprintf("Compromised Package: %s", dep.Name),
		Detail:      reason,
		Severity:    SeverityCritical,
		Remediation: fmt.Sprintf("Remove %s immediately and audit for data exfiltration", dep.Name),
		Metadata:    map[string]string{"package": dep.Name, "version": dep.Version, "reason": reason},
	}}
}

func (n *NPMSupplyChainScanner) checkTyposquat(dep Dependency) []Finding {
	if strings.HasPrefix(dep.Name, "@") || len(dep.Name) < 4 {
		return nil
	}

	for _, popular := range popularPackages {
		if dep.Name == popular {
			return nil
		}
	}

	for _, popular := range popularPackages {
		if levenshtein(dep.Name, popular) == 1 {
			return []Finding{typosquatFinding(n.Name(), dep, popular)}
		}
		if dep.Name == strings.ReplaceAll(popular, "-", "") ||
			dep.Name == strings.ReplaceAll(popular, "-", "_") ||
			dep.Name == popular+"s" || dep.Name+"s" == popular ||
			dep.Name == popular+"js" || dep.Name == popular+"-js" {
			return []Finding{typosquatFinding(n.Name(), dep, popular)}
		}
	}
	return nil
}

func typosquatFinding(scanner string, dep Dependency, popular string) Finding {
	return Finding{
		Scanner:     scanner,
		RuleID:      "typosquat-suspect",
		Title:       fmt.Sprintf("Possible Typosquat: %s", dep.Name),
		Detail:      fmt.Sprintf("'%s' is suspiciously similar to popular package '%s'", dep.Name, popular),
		Severity:    SeverityHigh,
		Remediation: fmt.Sprintf("Verify you intended to install '%s' and not '%s'", dep.Name, popular),
		Metadata:    map[string]string{"package": dep.Name, "similar_to": popular},
	}
}

func (n *NPMSupplyChainScanner) checkRegistry(dep Dependency) []Finding {
	var findings []Finding

	url := fmt.Sprintf("https://registry.npmjs.org/%s", dep.Name)
	resp, err := n.HTTPClient.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()

	var reg npmRegistryResponse
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		return nil
	}

	if n.CooldownDays > 0 {
		findings = append(findings, n.checkCooldown(dep, reg)...)
	}

	if n.CheckInstallScripts {
		findings = append(findings, n.checkInstallScripts(dep, reg)...)
	}

	return findings
}

func (n *NPMSupplyChainScanner) checkCooldown(dep Dependency, reg npmRegistryResponse) []Finding {
	var findings []Finding

	if pubStr, ok := reg.Time[dep.Version]; ok {
		pubDate, err := time.Parse(time.RFC3339, pubStr)
		if err == nil {
			age := time.Since(pubDate)
			cooldown := time.Duration(n.CooldownDays) * 24 * time.Hour
			if age < cooldown {
				daysOld := int(age.Hours() / 24)
				findings = append(findings, Finding{
					Scanner:     n.Name(),
					RuleID:      "npm-cooldown",
					Title:       fmt.Sprintf("New Version: %s@%s (%dd old)", dep.Name, dep.Version, daysOld),
					Detail:      fmt.Sprintf("Published %s — within %d-day cooldown window", pubDate.Format("2006-01-02"), n.CooldownDays),
					Severity:    SeverityMedium,
					Remediation: fmt.Sprintf("Wait %d more day(s) or verify the release is legitimate", n.CooldownDays-daysOld),
					Metadata: map[string]string{
						"package": dep.Name, "version": dep.Version,
						"published": pubDate.Format(time.RFC3339),
						"days_old":  fmt.Sprintf("%d", daysOld),
					},
				})
			}
		}
	}

	if created, ok := reg.Time["created"]; ok {
		createDate, err := time.Parse(time.RFC3339, created)
		if err == nil && time.Since(createDate) < 30*24*time.Hour {
			daysOld := int(time.Since(createDate).Hours() / 24)
			findings = append(findings, Finding{
				Scanner:     n.Name(),
				RuleID:      "npm-new-package",
				Title:       fmt.Sprintf("Brand New Package: %s", dep.Name),
				Detail:      fmt.Sprintf("Package created %s — only %d day(s) old", createDate.Format("2006-01-02"), daysOld),
				Severity:    SeverityHigh,
				Remediation: "New packages carry higher supply chain risk — verify legitimacy before adopting",
				Metadata:    map[string]string{"package": dep.Name, "created": createDate.Format(time.RFC3339)},
			})
		}
	}

	return findings
}

func (n *NPMSupplyChainScanner) checkInstallScripts(dep Dependency, reg npmRegistryResponse) []Finding {
	var findings []Finding

	raw, ok := reg.Versions[dep.Version]
	if !ok {
		return nil
	}

	var detail npmVersionScripts
	if err := json.Unmarshal(raw, &detail); err != nil {
		return nil
	}

	dangerousHooks := []string{"preinstall", "install", "postinstall"}
	for _, hook := range dangerousHooks {
		script, exists := detail.Scripts[hook]
		if !exists {
			continue
		}

		severity := SeverityMedium
		if hasSuspiciousCommand(script) {
			severity = SeverityHigh
		}

		findings = append(findings, Finding{
			Scanner:     n.Name(),
			RuleID:      "npm-install-script",
			Title:       fmt.Sprintf("Install Script: %s@%s has '%s'", dep.Name, dep.Version, hook),
			Detail:      fmt.Sprintf("Script: %s", truncate(script, 200)),
			Severity:    severity,
			Remediation: "Review the install script for malicious behavior; use --ignore-scripts if safe to skip",
			Metadata:    map[string]string{"package": dep.Name, "version": dep.Version, "hook": hook, "script": truncate(script, 500)},
		})
	}

	return findings
}

func hasSuspiciousCommand(script string) bool {
	lower := strings.ToLower(script)
	suspicious := []string{
		"curl ", "wget ", "eval(", "eval ", "base64",
		"/dev/tcp", "nc ", "netcat", "powershell",
		"cmd.exe", "chmod ", "exec(", "child_process",
		"http://", "https://",
	}
	for _, s := range suspicious {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			curr[j] = del
			if ins < curr[j] {
				curr[j] = ins
			}
			if sub < curr[j] {
				curr[j] = sub
			}
		}
		prev, curr = curr, prev
	}

	return prev[lb]
}
