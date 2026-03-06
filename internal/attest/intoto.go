package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/nitrogate/nitrogate/internal/gate"
	"github.com/nitrogate/nitrogate/internal/scanner"
)

const (
	InTotoStatementType = "https://in-toto.io/Statement/v1"
	ReviewPredicateType = "https://nitrogate.dev/attestation/review/v1"
)

type InTotoStatement struct {
	Type          string           `json:"_type"`
	Subject       []Subject        `json:"subject"`
	PredicateType string           `json:"predicateType"`
	Predicate     ReviewPredicate  `json:"predicate"`
}

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type ReviewPredicate struct {
	Gate        GateInfo              `json:"gate"`
	Scanners    []ScannerSummary      `json:"scanners"`
	Evidence    Evidence              `json:"evidence"`
	Findings    []scanner.Finding     `json:"findings"`
	Timestamp   string                `json:"timestamp"`
	Version     string                `json:"version"`
}

type GateInfo struct {
	Decision string   `json:"decision"`
	Mode     string   `json:"mode"`
	Reasons  []string `json:"reasons"`
	Summary  gate.GateSummary `json:"summary"`
}

type ScannerSummary struct {
	Name     string `json:"name"`
	Duration string `json:"duration"`
	Findings int    `json:"findings"`
	Error    string `json:"error,omitempty"`
}

type Evidence struct {
	Repo             string   `json:"repo"`
	PR               int      `json:"pr"`
	BaseSHA          string   `json:"baseSha"`
	HeadSHA          string   `json:"headSha"`
	ChangedFiles     []string `json:"changedFiles"`
	DiffSHA256       string   `json:"diffSha256"`
}

func BuildStatement(
	gateResult gate.GateResult,
	repo string,
	pr int,
	baseSHA, headSHA string,
	changedFiles []string,
	diff string,
) *InTotoStatement {
	diffHash := sha256Hex([]byte(diff))

	var scannerSummaries []ScannerSummary
	var allFindings []scanner.Finding
	for _, r := range gateResult.ScanResults {
		scannerSummaries = append(scannerSummaries, ScannerSummary{
			Name:     r.Scanner,
			Duration: r.Duration,
			Findings: len(r.Findings),
			Error:    r.Error,
		})
		allFindings = append(allFindings, r.Findings...)
	}

	commitDigest := sha256Hex([]byte(headSHA))

	return &InTotoStatement{
		Type: InTotoStatementType,
		Subject: []Subject{
			{
				Name:   repo,
				Digest: map[string]string{"sha256": commitDigest},
			},
		},
		PredicateType: ReviewPredicateType,
		Predicate: ReviewPredicate{
			Gate: GateInfo{
				Decision: string(gateResult.Decision),
				Mode:     gateResult.Mode,
				Reasons:  gateResult.Reasons,
				Summary:  gateResult.Summary,
			},
			Scanners:  scannerSummaries,
			Evidence: Evidence{
				Repo:         repo,
				PR:           pr,
				BaseSHA:      baseSHA,
				HeadSHA:      headSHA,
				ChangedFiles: changedFiles,
				DiffSHA256:   diffHash,
			},
			Findings:  allFindings,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Version:   "2.0.0",
		},
	}
}

func (s *InTotoStatement) ToJSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

func (s *InTotoStatement) PayloadHash() string {
	data, _ := json.Marshal(s)
	return sha256Hex(data)
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
