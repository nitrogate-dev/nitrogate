package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nitrogate/nitrogate/internal/attest"
	"github.com/nitrogate/nitrogate/internal/gate"
	"github.com/nitrogate/nitrogate/internal/guac"
	"github.com/nitrogate/nitrogate/internal/output"
	"github.com/nitrogate/nitrogate/internal/policy"
	"github.com/nitrogate/nitrogate/internal/scanner"
	gh "github.com/google/go-github/v60/github"
	"golang.org/x/oauth2"
)

func main() {
	token := envOrDefault("GITHUB_TOKEN", "")
	if token == "" {
		log.Fatal("GITHUB_TOKEN is required")
	}

	repoFullName := os.Getenv("GITHUB_REPOSITORY")
	prNumber := 0
	fmt.Sscanf(os.Getenv("NITROGATE_PR_NUMBER"), "%d", &prNumber)

	if os.Getenv("GITHUB_EVENT_NAME") == "pull_request" && prNumber == 0 {
		prNumber = parsePRNumberFromEvent()
	}

	if repoFullName == "" || prNumber == 0 {
		log.Fatal("GITHUB_REPOSITORY and PR number are required")
	}

	parts := strings.SplitN(repoFullName, "/", 2)
	if len(parts) != 2 {
		log.Fatal("Invalid GITHUB_REPOSITORY format")
	}
	owner, repo := parts[0], parts[1]

	policyPath := envOrDefault("NITROGATE_POLICY_PATH", ".nitrogate.json")
	repoRoot := envOrDefault("GITHUB_WORKSPACE", ".")
	outputDir := envOrDefault("NITROGATE_OUTPUT_DIR", filepath.Join(repoRoot, "nitrogate-artifacts"))
	signingKey := os.Getenv("NITRO_SIGNING_KEY_B64")

	pol, fromFile, err := policy.Load(repoRoot, policyPath)
	if err != nil {
		log.Fatalf("Failed to load policy: %v", err)
	}
	log.Printf("Policy loaded (from file: %v), mode: %s", fromFile, pol.Mode)

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	client := gh.NewClient(tc)

	changedFiles, diff, baseSHA, headSHA, err := fetchPRData(ctx, client, owner, repo, prNumber)
	if err != nil {
		log.Fatalf("Failed to fetch PR data: %v", err)
	}
	log.Printf("PR #%d: %d changed files, %d bytes diff", prNumber, len(changedFiles), len(diff))

	scanCtx := &scanner.ScanContext{
		Diff:         diff,
		ChangedFiles: changedFiles,
		RepoFullName: repoFullName,
		PRNumber:     prNumber,
		BaseSHA:      baseSHA,
		HeadSHA:      headSHA,
		RepoRoot:     repoRoot,
	}

	results := runScanners(pol, scanCtx)
	log.Printf("Scanners complete: %d results", len(results))

	threshold := pol.SeverityThreshold()
	gateResult := gate.Evaluate(pol.Mode, threshold, results)
	log.Printf("Gate decision: %s (%d findings)", gateResult.Decision, gateResult.Summary.TotalFindings)

	stmt := attest.BuildStatement(gateResult, repoFullName, prNumber, baseSHA, headSHA, changedFiles, diff)

	attestResult := "SKIPPED"
	var signed *attest.SignedAttestation
	if signingKey != "" {
		signed, err = attest.Sign(stmt, signingKey)
		if err != nil {
			log.Printf("ERROR: Signing failed: %v", err)
			attestResult = "FAIL"
		} else {
			valid, verr := attest.Verify(signed)
			if verr != nil || !valid {
				log.Printf("ERROR: Verification failed: %v", verr)
				attestResult = "FAIL"
			} else {
				attestResult = "SIGNED"
				log.Println("Attestation signed and verified: PASS")
			}
		}
	} else {
		log.Println("No signing key — attestation skipped")
	}

	if err := output.WriteArtifacts(outputDir, gateResult, signed); err != nil {
		log.Printf("WARNING: Failed to write artifacts: %v", err)
	}

	stmtJSON, _ := stmt.ToJSON()
	os.WriteFile(filepath.Join(outputDir, "statement.json"), stmtJSON, 0644)

	comment := output.BuildPRComment(gateResult, attestResult, signed)
	postPRComment(ctx, client, owner, repo, prNumber, comment)

	inlineComments := output.BuildInlineComments(gateResult)
	if len(inlineComments) > 0 {
		postPRReview(ctx, client, owner, repo, prNumber, headSHA, inlineComments)
	}

	if pol.GUAC.Enabled && signed != nil {
		guacClient := guac.NewClient(pol.GUAC.Endpoint)
		if err := guacClient.PushAttestation(signed, outputDir); err != nil {
			log.Printf("WARNING: GUAC push failed: %v", err)
		} else {
			log.Println("Attestation pushed to GUAC")
		}
		if err := guacClient.CertifyGate(repoFullName, headSHA, prNumber, gateResult); err != nil {
			log.Printf("WARNING: GUAC certify failed: %v", err)
		} else {
			log.Printf("GUAC certification: %s", gateResult.Decision)
		}
	}

	setOutput("attestation-result", attestResult)
	setOutput("gate-decision", string(gateResult.Decision))
	setOutput("total-findings", fmt.Sprintf("%d", gateResult.Summary.TotalFindings))
	setOutput("critical-count", fmt.Sprintf("%d", gateResult.Summary.CriticalCount))

	if pol.IsGateMode() && gateResult.Decision == gate.DecisionFail {
		log.Fatalf("NitroGate: Quality gate FAILED — %d blocking finding(s)", len(gateResult.Reasons))
	}
}

func runScanners(pol *policy.Policy, ctx *scanner.ScanContext) []scanner.ScanResult {
	var scanners []scanner.Scanner

	if pol.Secrets.Enabled {
		scanners = append(scanners, scanner.NewSecretScanner(
			pol.Secrets.AllowFiles, nil,
		))
	}

	if pol.Dependencies.Enabled {
		scanners = append(scanners, scanner.NewDepsScanner(
			pol.Dependencies.IgnoreVulns,
			pol.Dependencies.SeverityThreshold,
		))
	}

	if pol.Workflows.Enabled {
		scanners = append(scanners, scanner.NewWorkflowScanner(
			pol.Workflows.CheckScriptInjection,
			pol.Workflows.CheckPwnRequest,
			pol.Workflows.CheckExcessivePermissions,
			pol.Workflows.RequirePinnedActions,
			pol.Workflows.TrustedOrgs,
		))
	}

	if pol.Licenses.Enabled {
		scanners = append(scanners, scanner.NewLicenseScanner(
			pol.Licenses.Denied,
			pol.Licenses.WarnOn,
			pol.Licenses.AllowUnknown,
		))
	}

	npmCfg := pol.Dependencies.NPMSupplyChain
	if pol.Dependencies.Enabled && (npmCfg.CheckCompromised || npmCfg.CheckTyposquatting || npmCfg.CheckInstallScripts || npmCfg.CooldownDays > 0) {
		scanners = append(scanners, scanner.NewNPMSupplyChainScanner(
			npmCfg.CooldownDays,
			npmCfg.CheckCompromised,
			npmCfg.CheckTyposquatting,
			npmCfg.CheckInstallScripts,
		))
	}

	var results []scanner.ScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, s := range scanners {
		wg.Add(1)
		go func(sc scanner.Scanner) {
			defer wg.Done()
			result := sc.Scan(ctx)
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
			log.Printf("Scanner '%s': %d findings (%s)", result.Scanner, len(result.Findings), result.Duration)
		}(s)
	}

	wg.Wait()
	return results
}

func fetchPRData(ctx context.Context, client *gh.Client, owner, repo string, prNumber int) ([]string, string, string, string, error) {
	pr, _, err := client.PullRequests.Get(ctx, owner, repo, prNumber)
	if err != nil {
		return nil, "", "", "", fmt.Errorf("get PR: %w", err)
	}

	baseSHA := pr.GetBase().GetSHA()
	headSHA := pr.GetHead().GetSHA()

	opts := &gh.ListOptions{PerPage: 100}
	var allFiles []string
	for {
		files, resp, err := client.PullRequests.ListFiles(ctx, owner, repo, prNumber, opts)
		if err != nil {
			return nil, "", "", "", fmt.Errorf("list files: %w", err)
		}
		for _, f := range files {
			allFiles = append(allFiles, f.GetFilename())
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	diff, _, err := client.PullRequests.GetRaw(ctx, owner, repo, prNumber, gh.RawOptions{Type: gh.Diff})
	if err != nil {
		return nil, "", "", "", fmt.Errorf("get diff: %w", err)
	}

	return allFiles, diff, baseSHA, headSHA, nil
}

func postPRComment(ctx context.Context, client *gh.Client, owner, repo string, prNumber int, body string) {
	marker := "<!-- nitrogate-review -->"
	comments, _, err := client.Issues.ListComments(ctx, owner, repo, prNumber, &gh.IssueListCommentsOptions{
		ListOptions: gh.ListOptions{PerPage: 100},
	})
	if err != nil {
		log.Printf("WARNING: Failed to list comments: %v", err)
	}

	for _, c := range comments {
		if strings.Contains(c.GetBody(), marker) {
			_, _, err := client.Issues.EditComment(ctx, owner, repo, c.GetID(), &gh.IssueComment{Body: &body})
			if err != nil {
				log.Printf("WARNING: Failed to update comment: %v", err)
			} else {
				log.Println("PR comment updated")
			}
			return
		}
	}

	_, _, err = client.Issues.CreateComment(ctx, owner, repo, prNumber, &gh.IssueComment{Body: &body})
	if err != nil {
		log.Printf("WARNING: Failed to create comment: %v", err)
	} else {
		log.Println("PR comment created")
	}
}

func postPRReview(ctx context.Context, client *gh.Client, owner, repo string, prNumber int, commitID string, comments []output.InlineComment) {
	var reviewComments []*gh.DraftReviewComment
	side := "RIGHT"
	for _, c := range comments {
		reviewComments = append(reviewComments, &gh.DraftReviewComment{
			Path: gh.String(c.Path),
			Line: gh.Int(c.Line),
			Side: &side,
			Body: gh.String(c.Body),
		})
	}

	event := "COMMENT"
	review := &gh.PullRequestReviewRequest{
		CommitID: gh.String(commitID),
		Event:    &event,
		Comments: reviewComments,
	}

	_, _, err := client.PullRequests.CreateReview(ctx, owner, repo, prNumber, review)
	if err != nil {
		log.Printf("WARNING: Failed to create inline review: %v", err)
		log.Printf("  (Inline comments require the finding line to be within the PR diff)")
	} else {
		log.Printf("PR review created with %d inline comments", len(reviewComments))
	}
}

func parsePRNumberFromEvent() int {
	eventPath := os.Getenv("GITHUB_EVENT_PATH")
	if eventPath == "" {
		return 0
	}
	data, err := os.ReadFile(eventPath)
	if err != nil {
		return 0
	}
	var event struct {
		PullRequest struct {
			Number int `json:"number"`
		} `json:"pull_request"`
	}
	if err := json.Unmarshal(data, &event); err != nil {
		return 0
	}
	return event.PullRequest.Number
}

func setOutput(key, value string) {
	outputFile := os.Getenv("GITHUB_OUTPUT")
	if outputFile != "" {
		f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err == nil {
			defer f.Close()
			fmt.Fprintf(f, "%s=%s\n", key, value)
		}
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
