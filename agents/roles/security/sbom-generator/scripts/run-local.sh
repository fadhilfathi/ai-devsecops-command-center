#!/usr/bin/env bash
# run-local.sh — install the package in editable mode and start the
# service against a local Syft binary. Intended for development.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"

cd "${ROOT}"

if ! command -v syft >/dev/null 2>&1; then
    echo "!! syft not found on PATH. install with:" >&2
    echo "   curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "!! python3 not found on PATH." >&2
    exit 1
fi

PY="${PYTHON:-python3}"

echo ">> installing in editable mode"
"${PY}" -m pip install -e .[dev]

echo ">> starting service on :4007"
exec "${PY}" -m sbom_generator \
    --host 127.0.0.1 \
    --port "${PORT:-4007}" \
    --log-level "${LOG_LEVEL:-INFO}" \
    --syft-binary "$(command -v syft)" \
    --bus-url "${BUS_URL:-memory://}"
