# Example 06: GUAC Integration — Organizational Intelligence

## What This Tests

NitroGate pushes gate results into [GUAC](https://github.com/guacsec/guac) (Graph for Understanding Artifact Composition), enabling **org-wide security queries** like:

- "Which repos have failing quality gates?"
- "Show me all PRs merged without a passing quality gate"
- "What packages across all repos have critical vulnerabilities?"

## Prerequisites

```bash
# 1. Start GUAC (Docker required)
cd deploy/
curl -sL -o guac-demo-compose.yaml \
  https://github.com/guacsec/guac/releases/latest/download/guac-demo-compose.yaml
docker compose -f guac-demo-compose.yaml -p guac up -d

# 2. Verify GUAC is running
curl -s http://localhost:8080/query -H "Content-Type: application/json" \
  -d '{"query": "{ packages(pkgSpec: {}) { type } }"}' | python3 -m json.tool
```

## How to Run

### Step 1: Generate test attestation + SBOM

```bash
cd /path/to/nitrogate
go run test-guac/generate_attestation.go
```

This creates:
- `test-guac/attestation.json` — DSSE-wrapped in-toto attestation
- `test-guac/sbom.json` — SPDX SBOM for the repo

### Step 2: Ingest SBOM into GUAC

```bash
docker run --rm --network guac_default \
  -v "$(pwd)/test-guac:/data" \
  ghcr.io/guacsec/guac:v1.0.1 \
  /opt/guac/guacone collect files /data/sbom.json \
  --gql-addr http://graphql:8080/query \
  --csub-addr collectsub:2782
```

### Step 3: Push gate results via GraphQL

```bash
# Push a FAIL decision for repo "myorg/myrepo"
curl -s http://localhost:8080/query -H "Content-Type: application/json" -d '{
  "query": "mutation { ingestHasMetadata(subject: {package: {packageInput: {type: \"guac\", namespace: \"pkg/myorg\", name: \"myrepo\", version: \"1.0.0\"}}}, pkgMatchType: {pkg: SPECIFIC_VERSION}, hasMetadata: {key: \"nitrogate:decision\", value: \"FAIL\", justification: \"3 findings — 2 critical, 1 medium\", timestamp: \"2026-03-03T07:35:00Z\", origin: \"nitrogate\", collector: \"nitrogate-v1\", documentRef: \"nitrogate-pr123\"}) }"
}'

# Push PR metadata
curl -s http://localhost:8080/query -H "Content-Type: application/json" -d '{
  "query": "mutation { ingestHasMetadata(subject: {package: {packageInput: {type: \"guac\", namespace: \"pkg/myorg\", name: \"myrepo\", version: \"1.0.0\"}}}, pkgMatchType: {pkg: SPECIFIC_VERSION}, hasMetadata: {key: \"nitrogate:pr\", value: \"123\", justification: \"Quality gate ran on PR #123\", timestamp: \"2026-03-03T07:35:00Z\", origin: \"nitrogate\", collector: \"nitrogate-v1\", documentRef: \"nitrogate-pr123-meta\"}) }"
}'

# Push a PASS decision for a different repo
curl -s http://localhost:8080/query -H "Content-Type: application/json" -d '{
  "query": "mutation { ingestHasMetadata(subject: {package: {packageInput: {type: \"guac\", namespace: \"pkg/myorg\", name: \"safe-repo\", version: \"2.0.0\"}}}, pkgMatchType: {pkg: SPECIFIC_VERSION}, hasMetadata: {key: \"nitrogate:decision\", value: \"PASS\", justification: \"0 findings — all scanners passed\", timestamp: \"2026-03-03T08:00:00Z\", origin: \"nitrogate\", collector: \"nitrogate-v1\", documentRef: \"nitrogate-pr456\"}) }"
}'
```

### Step 4: Query — "Which repos are failing?"

```bash
curl -s http://localhost:8080/query -H "Content-Type: application/json" -d '{
  "query": "{ HasMetadata(hasMetadataSpec: {key: \"nitrogate:decision\", value: \"FAIL\"}) { id key value justification timestamp origin subject { __typename ... on Package { type namespaces { namespace names { name versions { version } } } } } } }"
}' | python3 -m json.tool
```

### Expected Output

```json
{
  "data": {
    "HasMetadata": [
      {
        "id": "10",
        "key": "nitrogate:decision",
        "value": "FAIL",
        "justification": "3 findings — 2 critical, 1 medium",
        "timestamp": "2026-03-03T07:35:00Z",
        "origin": "nitrogate",
        "subject": {
          "__typename": "Package",
          "type": "guac",
          "namespaces": [
            {
              "namespace": "pkg/myorg",
              "names": [
                {
                  "name": "myrepo",
                  "versions": [{ "version": "1.0.0" }]
                }
              ]
            }
          ]
        }
      }
    ]
  }
}
```

### Step 5: Query — "Show all NitroGate metadata"

```bash
curl -s http://localhost:8080/query -H "Content-Type: application/json" -d '{
  "query": "{ HasMetadata(hasMetadataSpec: {origin: \"nitrogate\"}) { id key value justification timestamp subject { __typename ... on Package { type namespaces { namespace names { name versions { version } } } } } } }"
}' | python3 -m json.tool
```

## What This Proves

1. **Every gate result is queryable** — not just pass/fail, but which PR, how many findings, when
2. **Cross-repo visibility** — one GUAC instance covers all repos in the org
3. **Compliance auditing** — "Prove that no PRs were merged without passing the quality gate"
4. **Incident response** — "Which repos use lodash@4.17.20?" → GUAC knows

## Architecture

```
PR opened → NitroGate scans → Gate decision
                                    ↓
                              GraphQL mutation
                                    ↓
                              GUAC (in-memory graph)
                                    ↓
                              Queryable via GraphQL
                                    ↓
                    "Which repos are failing?" → instant answer
```

## Teardown

```bash
docker compose -f deploy/guac-demo-compose.yaml -p guac down
```
