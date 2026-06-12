# Example requests

```bash
ENDPOINT=http://127.0.0.1:4007

# 1. Health check
curl -fsS ${ENDPOINT}/healthz | jq .

# 2. Generate a CycloneDX JSON for nginx:1.25
curl -fsS -X POST ${ENDPOINT}/v1/sbom/quick \
    -H 'Content-Type: application/json' \
    -d '{"source":"nginx:1.25","format":"cyclonedx-json"}' \
    | tee nginx.sbom.json | jq .components_count

# 3. Generate BOTH CycloneDX JSON and SPDX JSON for a git repo
curl -fsS -X POST ${ENDPOINT}/v1/sbom/generate \
    -H 'Content-Type: application/json' \
    -d '{
        "source": {"type":"git-repository","value":"https://github.com/aionrs/aionrs-command-center.git"},
        "formats": ["cyclonedx-json","spdx-json"]
    }' | jq '.formats | map({format, byte_size})'

# 4. Scan a local directory
curl -fsS -X POST ${ENDPOINT}/v1/sbom/generate \
    -H 'Content-Type: application/json' \
    -d '{
        "source": {"type":"directory","value":"."},
        "formats": ["spdx-tag-value"],
        "exclude_paths": [".git","node_modules","__pycache__",".venv"]
    }' | jq -r '.formats[0].body' > local.spdx

# 5. Enumerate a registry
curl -fsS -X POST ${ENDPOINT}/v1/sbom/generate \
    -H 'Content-Type: application/json' \
    -d '{
        "source": {"type":"registry","value":"https://registry.example.com"},
        "formats": ["cyclonedx-json"]
    }' | jq .components_count

# 6. Pull a CycloneDX XML
curl -fsS -X POST ${ENDPOINT}/v1/sbom/quick \
    -H 'Content-Type: application/json' \
    -d '{"source":"alpine:3.18","format":"cyclonedx-xml"}' \
    | jq -r '.formats[0].body' > alpine.sbom.xml
```
