#!/usr/bin/env bash
# build.sh — build the SBOM generator container image locally.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"

IMAGE_TAG="${IMAGE_TAG:-aionrs/sbom-generator:dev}"
SYFT_VERSION="${SYFT_VERSION:-1.6.0}"
PYTHON_VERSION="${PYTHON_VERSION:-3.11}"

echo ">> building ${IMAGE_TAG} (python=${PYTHON_VERSION}, syft=${SYFT_VERSION})"
docker build \
    --build-arg "PYTHON_VERSION=${PYTHON_VERSION}" \
    --build-arg "SYFT_VERSION=${SYFT_VERSION}" \
    -f "${ROOT}/Dockerfile" \
    -t "${IMAGE_TAG}" \
    "${ROOT}"

echo ">> done. image: ${IMAGE_TAG}"
echo "   run with:  docker run --rm -p 4007:4007 ${IMAGE_TAG}"
