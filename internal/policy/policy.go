package policy

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/nitrogate/nitrogate/internal/scanner"
)

type SecretPattern struct {
	Name     string `json:"name"`
	Regex    string `json:"regex"`
	Severity string `json:"severity"`
}

type SecretsConfig struct {
	Enabled           bool            `json:"enabled"`
	SeverityThreshold string          `json:"severityThreshold"`
	AllowFiles        []string        `json:"allowFiles"`
	CustomPatterns    []SecretPattern `json:"customPatterns"`
}

type NPMSupplyChainConfig struct {
	CooldownDays       int  `json:"cooldownDays"`
	CheckCompromised   bool `json:"checkCompromised"`
	CheckTyposquatting bool `json:"checkTyposquatting"`
	CheckInstallScripts bool `json:"checkInstallScripts"`
}

type DependenciesConfig struct {
	Enabled           bool                 `json:"enabled"`
	SeverityThreshold string               `json:"severityThreshold"`
	Ecosystems        []string             `json:"ecosystems"`
	IgnoreVulns       []string             `json:"ignoreVulns"`
	NPMSupplyChain    NPMSupplyChainConfig `json:"npmSupplyChain"`
}

type LicensesConfig struct {
	Enabled      bool     `json:"enabled"`
	Denied       []string `json:"denied"`
	WarnOn       []string `json:"warnOn"`
	AllowUnknown bool     `json:"allowUnknown"`
}

type WorkflowsConfig struct {
	Enabled                  bool     `json:"enabled"`
	RequirePinnedActions     bool     `json:"requirePinnedActions"`
	TrustedOrgs              []string `json:"trustedOrgs"`
	CheckScriptInjection     bool     `json:"checkScriptInjection"`
	CheckPwnRequest          bool     `json:"checkPwnRequest"`
	CheckExcessivePermissions bool    `json:"checkExcessivePermissions"`
}

type AttestationConfig struct {
	Format   string `json:"format"`
	Signing  string `json:"signing"`
	Fallback string `json:"sigstoreFallback"`
	Storage  string `json:"storage"`
}

type LLMConfig struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

type GUACConfig struct {
	Enabled  bool   `json:"enabled"`
	Endpoint string `json:"endpoint"`
}

type FilePolicy struct {
	AllowedFileGlobs []string `json:"allowedFileGlobs"`
	DeniedFileGlobs  []string `json:"deniedFileGlobs"`
	MaxChangedFiles  int      `json:"maxChangedFiles"`
	MaxDiffBytes     int      `json:"maxDiffBytes"`
}

type Policy struct {
	Mode         string             `json:"mode"`
	FilePolicy   FilePolicy         `json:"filePolicy"`
	Secrets      SecretsConfig      `json:"secrets"`
	Dependencies DependenciesConfig `json:"dependencies"`
	Licenses     LicensesConfig     `json:"licenses"`
	Workflows    WorkflowsConfig    `json:"workflows"`
	Attestation  AttestationConfig  `json:"attestation"`
	LLM          LLMConfig          `json:"llm"`
	GUAC         GUACConfig         `json:"guac"`
}

var DefaultPolicy = Policy{
	Mode: "advisory",
	FilePolicy: FilePolicy{
		AllowedFileGlobs: []string{"**/*"},
		DeniedFileGlobs:  []string{"**/.env", "**/.env.*", "**/*.pem", "**/*.key", "**/credentials.json"},
		MaxChangedFiles:  100,
		MaxDiffBytes:     500000,
	},
	Secrets: SecretsConfig{
		Enabled:           true,
		SeverityThreshold: "high",
		AllowFiles:        []string{"**/*.test.*", "**/*.spec.*", "**/*.example"},
	},
	Dependencies: DependenciesConfig{
		Enabled:           true,
		SeverityThreshold: "high",
		Ecosystems:        []string{"npm", "go", "pypi"},
		NPMSupplyChain: NPMSupplyChainConfig{
			CooldownDays:       7,
			CheckCompromised:   true,
			CheckTyposquatting: true,
			CheckInstallScripts: true,
		},
	},
	Licenses: LicensesConfig{
		Enabled:      true,
		Denied:       []string{"AGPL-3.0", "GPL-3.0"},
		WarnOn:       []string{"LGPL-2.1", "MPL-2.0"},
		AllowUnknown: false,
	},
	Workflows: WorkflowsConfig{
		Enabled:                  true,
		RequirePinnedActions:     true,
		TrustedOrgs:              []string{"actions", "github", "google-github-actions"},
		CheckScriptInjection:     true,
		CheckPwnRequest:          true,
		CheckExcessivePermissions: true,
	},
	Attestation: AttestationConfig{
		Format:  "intoto-v1",
		Signing: "ed25519",
		Storage: "artifact",
	},
	LLM: LLMConfig{
		Provider: "mock",
		Model:    "gpt-4o",
	},
	GUAC: GUACConfig{
		Enabled:  false,
		Endpoint: "http://localhost:8080/query",
	},
}

func Load(repoRoot, policyPath string) (*Policy, bool, error) {
	fullPath := filepath.Join(repoRoot, policyPath)

	data, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			p := DefaultPolicy
			return &p, false, nil
		}
		return nil, false, err
	}

	p := DefaultPolicy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, false, err
	}

	applyDefaults(&p)
	return &p, true, nil
}

func applyDefaults(p *Policy) {
	if p.Mode == "" {
		p.Mode = "advisory"
	}
	if p.FilePolicy.MaxChangedFiles == 0 {
		p.FilePolicy.MaxChangedFiles = 100
	}
	if p.FilePolicy.MaxDiffBytes == 0 {
		p.FilePolicy.MaxDiffBytes = 500000
	}
	if len(p.FilePolicy.AllowedFileGlobs) == 0 {
		p.FilePolicy.AllowedFileGlobs = []string{"**/*"}
	}
	if p.Dependencies.NPMSupplyChain.CooldownDays == 0 {
		p.Dependencies.NPMSupplyChain.CooldownDays = 7
	}
}

func (p *Policy) SeverityThreshold() scanner.Severity {
	switch p.Mode {
	case "gate":
		return scanner.ParseSeverity(p.Secrets.SeverityThreshold)
	default:
		return scanner.SeverityCritical + 1
	}
}

func (p *Policy) IsGateMode() bool {
	return p.Mode == "gate"
}
