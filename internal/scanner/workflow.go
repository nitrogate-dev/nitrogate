package scanner

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

type WorkflowScanner struct {
	CheckScriptInjection     bool
	CheckPwnRequest          bool
	CheckExcessivePermissions bool
	RequirePinnedActions     bool
	TrustedOrgs              []string
}

func NewWorkflowScanner(checkInjection, checkPwn, checkPerms, requirePinned bool, trustedOrgs []string) *WorkflowScanner {
	return &WorkflowScanner{
		CheckScriptInjection:     checkInjection,
		CheckPwnRequest:          checkPwn,
		CheckExcessivePermissions: checkPerms,
		RequirePinnedActions:     requirePinned,
		TrustedOrgs:              trustedOrgs,
	}
}

func (w *WorkflowScanner) Name() string { return "workflows" }

func (w *WorkflowScanner) Scan(ctx *ScanContext) ScanResult {
	start := time.Now()
	var findings []Finding

	workflowFiles := filterWorkflowFiles(ctx.ChangedFiles)
	if len(workflowFiles) == 0 {
		return ScanResult{
			Scanner:  "workflows",
			Findings: nil,
			Duration: time.Since(start).String(),
		}
	}

	workflowDiffs := extractWorkflowDiffs(ctx.Diff, workflowFiles)

	for file, content := range workflowDiffs {
		if w.CheckScriptInjection {
			findings = append(findings, w.detectScriptInjection(file, content)...)
		}
		if w.CheckPwnRequest {
			findings = append(findings, w.detectPwnRequest(file, content)...)
		}
		if w.RequirePinnedActions {
			findings = append(findings, w.checkActionPinning(file, content)...)
		}
		if w.CheckExcessivePermissions {
			findings = append(findings, w.checkPermissions(file, content)...)
		}
		findings = append(findings, w.checkSecretsInLogs(file, content)...)
	}

	return ScanResult{
		Scanner:  "workflows",
		Findings: findings,
		Duration: time.Since(start).String(),
	}
}

var dangerousContexts = []string{
	"github.event.issue.title",
	"github.event.issue.body",
	"github.event.pull_request.title",
	"github.event.pull_request.body",
	"github.event.comment.body",
	"github.event.review.body",
	"github.event.review_comment.body",
	"github.event.pages.*.page_name",
	"github.event.commits.*.message",
	"github.event.head_commit.message",
	"github.event.head_commit.author.email",
	"github.event.head_commit.author.name",
	"github.event.commits.*.author.email",
	"github.event.commits.*.author.name",
	"github.event.pull_request.head.ref",
	"github.event.pull_request.head.label",
	"github.event.pull_request.head.repo.default_branch",
	"github.head_ref",
}

func (w *WorkflowScanner) detectScriptInjection(file, content string) []Finding {
	var findings []Finding
	lines := strings.Split(content, "\n")

	inRunBlock := false
	runLine := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "run:") || strings.HasPrefix(trimmed, "run: |") {
			inRunBlock = true
			runLine = i + 1
		} else if inRunBlock && !strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "\t") && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			inRunBlock = false
		}

		if !inRunBlock && !strings.HasPrefix(trimmed, "run:") {
			continue
		}

		for _, ctx := range dangerousContexts {
			pattern := "${{ " + ctx + " }}"
			patternNoSpace := "${{" + ctx + "}}"

			if strings.Contains(line, pattern) || strings.Contains(line, patternNoSpace) {
				findings = append(findings, Finding{
					Scanner:  "workflows",
					RuleID:   "script-injection",
					Title:    "Script Injection Vulnerability",
					Detail:   fmt.Sprintf("Dangerous use of '%s' in run block. An attacker can craft a malicious %s to inject arbitrary commands.", ctx, contextToSource(ctx)),
					Severity: SeverityCritical,
					File:     file,
					Line:     runLine,
					Remediation: fmt.Sprintf("Use an environment variable instead:\nenv:\n  VALUE: ${{ %s }}\nrun: echo \"$VALUE\"", ctx),
					Metadata: map[string]string{
						"context": ctx,
						"type":    "script-injection",
					},
				})
			}
		}
	}

	return findings
}

func (w *WorkflowScanner) detectPwnRequest(file, content string) []Finding {
	var findings []Finding

	hasPRTarget := regexp.MustCompile(`(?m)^\s*on:\s*\n\s*pull_request_target:|on:\s*\[.*pull_request_target.*\]|on:\s*pull_request_target`).MatchString(content)
	if !hasPRTarget {
		return findings
	}

	checkoutPRHead := regexp.MustCompile(`(?s)uses:\s*actions/checkout.*ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)\s*\}\}`)
	if checkoutPRHead.MatchString(content) {
		findings = append(findings, Finding{
			Scanner:     "workflows",
			RuleID:      "pwn-request",
			Title:       "Pwn Request Vulnerability",
			Detail:      "Workflow uses pull_request_target with checkout of PR head. This allows fork PRs to execute code with access to the base repo's secrets.",
			Severity:    SeverityCritical,
			File:        file,
			Remediation: "Use 'pull_request' trigger instead, or avoid checking out the PR head code. If you must use pull_request_target, don't run PR code in the same job that has secret access.",
			Metadata: map[string]string{
				"type":    "pwn-request",
				"trigger": "pull_request_target",
			},
		})
	}

	return findings
}

func (w *WorkflowScanner) checkActionPinning(file, content string) []Finding {
	var findings []Finding
	usesRe := regexp.MustCompile(`uses:\s*([^\s]+)`)
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		matches := usesRe.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}
		action := matches[1]

		if strings.HasPrefix(action, "./") || strings.HasPrefix(action, "docker://") {
			continue
		}

		parts := strings.SplitN(action, "@", 2)
		if len(parts) != 2 {
			continue
		}

		org := strings.Split(parts[0], "/")[0]
		ref := parts[1]

		if w.isTrustedOrg(org) && isSemverTag(ref) {
			continue
		}

		isSHA := regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(ref)
		if isSHA {
			continue
		}

		if ref == "main" || ref == "master" {
			findings = append(findings, Finding{
				Scanner:     "workflows",
				RuleID:      "unpinned-action-branch",
				Title:       "Action Pinned to Branch",
				Detail:      fmt.Sprintf("Action '%s' is pinned to branch '%s'. Branches are mutable — a compromised action can silently change.", parts[0], ref),
				Severity:    SeverityHigh,
				File:        file,
				Line:        i + 1,
				Remediation: fmt.Sprintf("Pin to a full commit SHA: %s@<commit-sha> # %s", parts[0], ref),
				Metadata: map[string]string{
					"action": action,
					"type":   "branch-pin",
				},
			})
		} else if isSemverTag(ref) {
			findings = append(findings, Finding{
				Scanner:     "workflows",
				RuleID:      "unpinned-action-tag",
				Title:       "Action Pinned to Mutable Tag",
				Detail:      fmt.Sprintf("Action '%s' is pinned to tag '%s'. Tags can be moved to point to different commits.", parts[0], ref),
				Severity:    SeverityMedium,
				File:        file,
				Line:        i + 1,
				Remediation: fmt.Sprintf("Pin to a full commit SHA: %s@<commit-sha> # %s", parts[0], ref),
				Metadata: map[string]string{
					"action": action,
					"type":   "tag-pin",
				},
			})
		}
	}

	return findings
}

func (w *WorkflowScanner) checkPermissions(file, content string) []Finding {
	var findings []Finding

	if strings.Contains(content, "permissions: write-all") {
		findings = append(findings, Finding{
			Scanner:     "workflows",
			RuleID:      "excessive-permissions",
			Title:       "Excessive Workflow Permissions",
			Detail:      "Workflow uses 'permissions: write-all', granting full write access to all scopes.",
			Severity:    SeverityHigh,
			File:        file,
			Remediation: "Use least-privilege permissions. Specify only the scopes needed (e.g., contents: read, pull-requests: write).",
			Metadata:    map[string]string{"type": "excessive-permissions"},
		})
	}

	return findings
}

func (w *WorkflowScanner) checkSecretsInLogs(file, content string) []Finding {
	var findings []Finding
	secretsInEcho := regexp.MustCompile(`(?i)(echo|printf|print)\s+.*\$\{\{\s*secrets\.[^}]+\}\}`)
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		if secretsInEcho.MatchString(line) {
			findings = append(findings, Finding{
				Scanner:     "workflows",
				RuleID:      "secrets-in-logs",
				Title:       "Secrets Exposed in Logs",
				Detail:      "Workflow may print secrets to CI logs via echo/printf.",
				Severity:    SeverityCritical,
				File:        file,
				Line:        i + 1,
				Remediation: "Never echo secrets. Use them only in environment variables or masked inputs.",
				Metadata:    map[string]string{"type": "secrets-in-logs"},
			})
		}
	}

	return findings
}

func (w *WorkflowScanner) isTrustedOrg(org string) bool {
	for _, trusted := range w.TrustedOrgs {
		if strings.EqualFold(org, trusted) {
			return true
		}
	}
	return false
}

func filterWorkflowFiles(files []string) []string {
	var result []string
	for _, f := range files {
		if strings.HasPrefix(f, ".github/workflows/") && (strings.HasSuffix(f, ".yml") || strings.HasSuffix(f, ".yaml")) {
			result = append(result, f)
		}
	}
	return result
}

func extractWorkflowDiffs(diff string, workflowFiles []string) map[string]string {
	result := make(map[string]string)
	sections := strings.Split(diff, "diff --git")

	for _, section := range sections {
		for _, file := range workflowFiles {
			if strings.Contains(section, file) {
				var addedLines []string
				for _, line := range strings.Split(section, "\n") {
					if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
						addedLines = append(addedLines, line[1:])
					}
				}
				result[file] = strings.Join(addedLines, "\n")
			}
		}
	}

	return result
}

func contextToSource(ctx string) string {
	if strings.Contains(ctx, "issue.title") {
		return "issue title"
	}
	if strings.Contains(ctx, "issue.body") {
		return "issue body"
	}
	if strings.Contains(ctx, "pull_request.title") {
		return "pull request title"
	}
	if strings.Contains(ctx, "pull_request.body") {
		return "pull request body"
	}
	if strings.Contains(ctx, "comment.body") {
		return "comment"
	}
	if strings.Contains(ctx, "head_commit.message") {
		return "commit message"
	}
	if strings.Contains(ctx, "head.ref") || strings.Contains(ctx, "head_ref") {
		return "branch name"
	}
	return "user-controlled input"
}

func isSemverTag(ref string) bool {
	return regexp.MustCompile(`^v?\d+(\.\d+)*$`).MatchString(ref)
}
