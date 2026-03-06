#!/bin/bash
set -e

GUAC_ENDPOINT="${GUAC_ENDPOINT:-http://localhost:9080/query}"

echo "=== NitroGate GUAC Demo ==="
echo "Endpoint: $GUAC_ENDPOINT"
echo ""

echo "--- Step 1: Ingest packages + gate results for 3 repos ---"
echo ""

# Helper: ingest package first, then add metadata
ingest() {
  local NS=$1 NAME=$2 VER=$3 KEY=$4 VAL=$5 JUST=$6 DOC=$7
  # Create package node
  curl -s "$GUAC_ENDPOINT" -H "Content-Type: application/json" -d "{
    \"query\": \"mutation { ingestPackage(pkg: {packageInput: {type: \\\"guac\\\", namespace: \\\"$NS\\\", name: \\\"$NAME\\\", version: \\\"$VER\\\"}}) { packageTypeID } }\"
  }" > /dev/null
  # Add metadata
  curl -s "$GUAC_ENDPOINT" -H "Content-Type: application/json" -d "{
    \"query\": \"mutation { ingestHasMetadata(subject: {package: {packageInput: {type: \\\"guac\\\", namespace: \\\"$NS\\\", name: \\\"$NAME\\\", version: \\\"$VER\\\"}}}, pkgMatchType: {pkg: SPECIFIC_VERSION}, hasMetadata: {key: \\\"$KEY\\\", value: \\\"$VAL\\\", justification: \\\"$JUST\\\", timestamp: \\\"2026-03-03T10:00:00Z\\\", origin: \\\"nitrogate\\\", collector: \\\"nitrogate-v1\\\", documentRef: \\\"$DOC\\\"}) }\"
  }" > /dev/null
}

# Repo 1: FAIL (secrets + npm supply chain)
ingest "pkg/myorg" "payment-service" "abc123" "nitrogate:decision" "FAIL" \
  "2 critical: AWS key leaked + compromised npm package (event-stream)" "nitrogate-payment-pr42"
echo "  [FAIL] payment-service PR#42 — AWS key + event-stream"

# Repo 2: PASS (clean)
ingest "pkg/myorg" "docs-site" "def456" "nitrogate:decision" "PASS" \
  "0 findings across 5 scanners" "nitrogate-docs-pr15"
echo "  [PASS] docs-site PR#15 — clean"

# Repo 3: FAIL (workflow injection)
ingest "pkg/myorg" "api-gateway" "ghi789" "nitrogate:decision" "FAIL" \
  "1 critical: script injection in CI workflow" "nitrogate-api-pr88"
echo "  [FAIL] api-gateway PR#88 — script injection in workflow"

echo ""
echo "--- Step 2: Query — Which repos are failing? ---"
echo ""
curl -s "$GUAC_ENDPOINT" -H "Content-Type: application/json" -d '{
  "query": "{ HasMetadata(hasMetadataSpec: {key: \"nitrogate:decision\", value: \"FAIL\"}) { key value justification timestamp subject { __typename ... on Package { namespaces { namespace names { name versions { version } } } } } } }"
}' | python3 -m json.tool

echo ""
echo "--- Step 3: Query — All NitroGate results ---"
echo ""
curl -s "$GUAC_ENDPOINT" -H "Content-Type: application/json" -d '{
  "query": "{ HasMetadata(hasMetadataSpec: {origin: \"nitrogate\"}) { key value justification timestamp subject { __typename ... on Package { namespaces { namespace names { name versions { version } } } } } } }"
}' | python3 -m json.tool

echo ""
echo "=== Demo complete ==="
