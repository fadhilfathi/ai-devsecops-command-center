# Convenience targets for the SBOM generator.
# The Makefile is intentionally tiny — the project uses pyproject.toml
# for everything that needs to be reproducible.

.PHONY: help install install-dev test test-cov lint format typecheck run \
        docker-build docker-run clean sbom-self

PY ?= python3
PORT ?= 4007

help:
	@echo "Targets:"
	@echo "  install      install the package (runtime deps)"
	@echo "  install-dev  install with dev deps"
	@echo "  test         run the test suite"
	@echo "  test-cov     run the test suite with coverage"
	@echo "  lint         run ruff"
	@echo "  format       run ruff format"
	@echo "  typecheck    run mypy"
	@echo "  run          start the service on :$${PORT:-4007}"
	@echo "  docker-build build the container image"
	@echo "  docker-run   run the container locally"
	@echo "  sbom-self    generate a CycloneDX SBOM for the agent itself"
	@echo "  clean        remove build / cache artefacts"

install:
	$(PY) -m pip install -e .

install-dev:
	$(PY) -m pip install -e .[dev]

test:
	$(PY) -m pytest

test-cov:
	$(PY) -m pytest --cov=src/sbom_generator --cov-report=term-missing --cov-report=xml

lint:
	$(PY) -m ruff check src tests

format:
	$(PY) -m ruff format src tests
	$(PY) -m ruff check --fix src tests

typecheck:
	$(PY) -m mypy src

run:
	$(PY) -m sbom_generator --host 0.0.0.0 --port $(PORT)

docker-build:
	./scripts/build.sh

docker-run:
	docker run --rm -p $(PORT):4007 aionrs/sbom-generator:dev

sbom-self:
	@curl -fsS -X POST http://127.0.0.1:$(PORT)/v1/sbom/quick \
	    -H 'Content-Type: application/json' \
	    -d '{"source":".","format":"cyclonedx-json"}' \
	    | jq -r '.formats[0].body' > sbom-generator.sbom.json
	@echo "wrote sbom-generator.sbom.json"

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache .mypy_cache .coverage coverage.xml
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
