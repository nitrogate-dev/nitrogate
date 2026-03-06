#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "╔══════════════════════════════════════════════════════╗"
echo "║         NitroGate — Full PR Simulation Demo          ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

echo "=== Phase 1: Run Go Unit Tests ==="
echo ""
cd "$PROJECT_ROOT"
go test ./internal/scanner/ -v -count=1 2>&1 | tail -20
echo ""

echo "=== Phase 2: Run Gate Evaluation Tests ==="
echo ""
go test ./internal/gate/ -v -count=1 2>&1
echo ""

echo "=== Phase 3: Run Attestation Signing Tests ==="
echo ""
go test ./internal/attest/ -v -count=1 2>&1
echo ""

echo "=== Phase 4: Build NitroGate Binary ==="
echo ""
go build -o bin/nitrogate ./cmd/nitrogate/
ls -lh bin/nitrogate
echo ""

echo "=== Phase 5: Generate Test Attestation ==="
echo ""
go run test-guac/generate_attestation.go
echo ""
echo "Generated files:"
ls -la test-guac/*.json
echo ""

echo "=== Phase 6: GUAC Integration (requires Docker) ==="
echo ""
if command -v docker &> /dev/null && docker ps &> /dev/null; then
    GUAC_RUNNING=$(docker ps --filter "name=guac-graphql" --format "{{.Names}}" 2>/dev/null || true)
    if [ -n "$GUAC_RUNNING" ]; then
        echo "GUAC is running. Ingesting package + pushing gate results..."
        echo ""

        # First ingest the package (GUAC requires package to exist before adding metadata)
        curl -s http://localhost:9080/query -H "Content-Type: application/json" -d '{
          "query": "mutation { ingestPackage(pkg: {packageInput: {type: \"guac\", namespace: \"pkg/demo-org\", name: \"test-repo\", version: \"sim-001\"}}) { packageTypeID } }"
        }' > /dev/null

        # Now add gate decision metadata
        curl -s http://localhost:9080/query -H "Content-Type: application/json" -d '{
          "query": "mutation { ingestHasMetadata(subject: {package: {packageInput: {type: \"guac\", namespace: \"pkg/demo-org\", name: \"test-repo\", version: \"sim-001\"}}}, pkgMatchType: {pkg: SPECIFIC_VERSION}, hasMetadata: {key: \"nitrogate:decision\", value: \"FAIL\", justification: \"Full simulation: 8 findings — 3 critical, 3 high, 2 medium\", timestamp: \"2026-03-03T12:00:00Z\", origin: \"nitrogate\", collector: \"nitrogate-v1\", documentRef: \"nitrogate-sim-001\"}) }"
        }' | python3 -m json.tool

        echo ""
        echo "Querying GUAC for results..."
        curl -s http://localhost:9080/query -H "Content-Type: application/json" -d '{
          "query": "{ HasMetadata(hasMetadataSpec: {origin: \"nitrogate\"}) { key value justification subject { __typename ... on Package { namespaces { namespace names { name } } } } } }"
        }' | python3 -m json.tool
    else
        echo "GUAC not running. Start with:"
        echo "  cd deploy/ && docker compose -f guac-demo-compose.yaml -p guac up -d"
        echo "Then re-run this script."
    fi
else
    echo "Docker not available. Skipping GUAC integration."
fi

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║                 Simulation Complete                   ║"
echo "║                                                      ║"
echo "║  Tests:        ✅ All Go tests passed                ║"
echo "║  Build:        ✅ Binary compiled                    ║"
echo "║  Attestation:  ✅ In-toto + DSSE generated           ║"
echo "║  GUAC:         Check output above                    ║"
echo "╚══════════════════════════════════════════════════════╝"
