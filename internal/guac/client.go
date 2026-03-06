package guac

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/nitrogate/nitrogate/internal/attest"
	"github.com/nitrogate/nitrogate/internal/gate"
)

type Client struct {
	Endpoint   string
	HTTPClient *http.Client
}

func NewClient(endpoint string) *Client {
	return &Client{
		Endpoint:   endpoint,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) PushAttestation(signed *attest.SignedAttestation, outputDir string) error {
	attestPath := filepath.Join(outputDir, "attestation.json")
	data, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal attestation: %w", err)
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	return os.WriteFile(attestPath, data, 0644)
}

func (c *Client) CertifyGate(repo, sha string, prNumber int, result gate.GateResult) error {
	parts := splitRepo(repo)
	now := time.Now().UTC().Format(time.RFC3339)
	docRef := fmt.Sprintf("nitrogate-%s-pr%d-%s", sha[:8], prNumber, time.Now().Format("20060102"))

	pkgType := "guac"
	namespace := fmt.Sprintf("pkg/%s", parts[0])
	name := parts[1]
	version := sha

	// Ensure package node exists in GUAC before adding metadata
	ingestPkg := `mutation($pkgType: String!, $namespace: String!, $name: String!, $version: String!) {
		ingestPackage(pkg: {packageInput: {type: $pkgType, namespace: $namespace, name: $name, version: $version}}) {
			packageTypeID
		}
	}`
	pkgVars := map[string]interface{}{
		"pkgType": pkgType, "namespace": namespace, "name": name, "version": version,
	}
	if _, err := c.Query(ingestPkg, pkgVars); err != nil {
		return fmt.Errorf("GUAC ingestPackage: %w", err)
	}

	justification := fmt.Sprintf("nitrogate: %s — %d findings (%d critical, %d high)",
		result.Decision,
		result.Summary.TotalFindings,
		result.Summary.CriticalCount,
		result.Summary.HighCount,
	)

	metadataEntries := []struct {
		Key, Value, Justification string
	}{
		{"nitrogate:decision", string(result.Decision), justification},
		{"nitrogate:pr", fmt.Sprintf("%d", prNumber), fmt.Sprintf("Quality gate ran on PR #%d", prNumber)},
		{"nitrogate:critical-findings", fmt.Sprintf("%d", result.Summary.CriticalCount), buildFindingSummary(result)},
	}

	for i, entry := range metadataEntries {
		query := `mutation($key: String!, $value: String!, $justification: String!, $timestamp: Time!, $docRef: String!, $pkgType: String!, $namespace: String!, $name: String!, $version: String!) {
			ingestHasMetadata(
				subject: {package: {packageInput: {type: $pkgType, namespace: $namespace, name: $name, version: $version}}},
				pkgMatchType: {pkg: SPECIFIC_VERSION},
				hasMetadata: {key: $key, value: $value, justification: $justification, timestamp: $timestamp, origin: "nitrogate", collector: "nitrogate-v1", documentRef: $docRef}
			)
		}`

		vars := map[string]interface{}{
			"key":           entry.Key,
			"value":         entry.Value,
			"justification": entry.Justification,
			"timestamp":     now,
			"docRef":        fmt.Sprintf("%s-%d", docRef, i),
			"pkgType":       pkgType,
			"namespace":     namespace,
			"name":          name,
			"version":       version,
		}

		if _, err := c.Query(query, vars); err != nil {
			return fmt.Errorf("GUAC certify %s: %w", entry.Key, err)
		}
	}

	return nil
}

func buildFindingSummary(result gate.GateResult) string {
	summary := ""
	for _, reason := range result.Reasons {
		if summary != "" {
			summary += "; "
		}
		summary += reason
	}
	if len(summary) > 500 {
		summary = summary[:497] + "..."
	}
	return summary
}

func splitRepo(repo string) [2]string {
	for i, c := range repo {
		if c == '/' {
			return [2]string{repo[:i], repo[i+1:]}
		}
	}
	return [2]string{"unknown", repo}
}

type GraphQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

type GraphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors,omitempty"`
}

func (c *Client) Query(query string, variables map[string]interface{}) (json.RawMessage, error) {
	reqBody, err := json.Marshal(GraphQLRequest{Query: query, Variables: variables})
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Post(c.Endpoint, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("GUAC query failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var gqlResp GraphQLResponse
	if err := json.Unmarshal(body, &gqlResp); err != nil {
		return nil, err
	}

	if len(gqlResp.Errors) > 0 {
		return nil, fmt.Errorf("GUAC GraphQL error: %s", gqlResp.Errors[0].Message)
	}

	return gqlResp.Data, nil
}

func (c *Client) QueryFailedGates() (json.RawMessage, error) {
	query := `{
		HasMetadata(hasMetadataSpec: {key: "nitrogate:decision", value: "FAIL"}) {
			id key value justification timestamp origin
			subject {
				... on Package {
					type
					namespaces { namespace names { name versions { version } } }
				}
			}
		}
	}`
	return c.Query(query, nil)
}

func (c *Client) QueryGateResults() (json.RawMessage, error) {
	query := `{
		HasMetadata(hasMetadataSpec: {origin: "nitrogate"}) {
			id key value justification timestamp
			subject {
				... on Package {
					type
					namespaces { namespace names { name versions { version } } }
				}
			}
		}
	}`
	return c.Query(query, nil)
}

func (c *Client) QueryVulnerabilities(vulnID string) (json.RawMessage, error) {
	query := `query($vulnID: String!) {
		vulnerabilities(vulnerabilitySpec: {vulnerabilityID: $vulnID}) {
			type
			vulnerabilityIDs { vulnerabilityID }
		}
	}`
	return c.Query(query, map[string]interface{}{"vulnID": vulnID})
}
