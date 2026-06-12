#!/usr/bin/env bash
# generate.sh — example CLI invocations against a running SBOM
# generator. Demonstrates the most common request payloads.
set -euo pipefail

ENDPOINT="${ENDPOINT:-http://127.0.0.1:4007}"

show() {
    echo
    echo "=============================================================="
    echo "$1"
    echo "=============================================================="
}

show "1. health check"
curl -fsS "${ENDPOINT}/healthz" | jq .

show "2. generate CycloneDX JSON for the official nginx image"
curl -fsS -X POST "${ENDPOINT}/v1/sbom/quick" \
    -H "Content-Type: application/json" \
    -d '{"source":"nginx:1.25","format":"cyclonedx-json"}' \
    | jq '.components_count, .format, (.formats[0].byte_size)'

show "3. full payload — git repository → SPDX tag-value"
curl -fsS -X POST "${ENDPOINT}/v1/sbom/generate" \
    -H "Content-Type: application/json" \
    -d '{
        "source": {"type":"git-repository","value":"https://github.com/aionrs/aionrs-command-center.git"},
        "formats": ["spdx-tag-value"],
        "include_dev_dependencies": false
    }' | jq '.components_count, .format, .warnings'

show "4. local directory → both CycloneDX JSON and SPDX JSON"
curl -fsS -X POST "${ENDPOINT}/v1/sbom/generate" \
    -H "Content-Type: application/json" \
    -d '{
        "source": {"type":"directory","value":"."},
        "formats": ["cyclonedx-json","spdx-json"],
        "exclude_paths": [".git","node_modules","__pycache__"]
    }' | jq '.components_count, .format, (.formats | length)'
