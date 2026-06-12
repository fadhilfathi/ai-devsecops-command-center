# Convenience targets for the SBOM pipeline service.

.PHONY: help install install-dev test test-cov lint format typecheck run \
        docker-build docker-run clean cli-generate cli-list

PY ?= python3
PORT ?= 4007

help:
	@echo "Targets:"
	@echo "  install         install runtime deps"
	@echo "  install-dev     install with dev deps"
	@echo "  test            run the test suite"
	@echo "  test-cov        run the test suite with coverage"
	@echo "  lint            run ruff"
	@echo "  format          run ruff format"
	@echo "  typecheck       run mypy"
	@echo "  run             start the service on :$${PORT:-4007}"
	@echo "  docker-build    build the container image"
	@echo "  docker-run      run the container locally"
	@echo "  cli-generate    example: docker:nginx:1.25 via the CLI"
	@echo "  cli-list        list stored SBOMs via the CLI"
	@echo "  clean           remove build / cache artefacts"

install:
	$(PY) -m pip install -e .

install-dev:
	$(PY) -m pip install -e .[dev]

test:
	$(PY) -m pytest

test-cov:
	$(PY) -m pytest --cov=src/sbom_pipeline --cov-report=term-missing --cov-report=xml

lint:
	$(PY) -m ruff check src tests

format:
	$(PY) -m ruff format src tests
	$(PY) -m ruff check --fix src tests

typecheck:
	$(PY) -m mypy src

run:
	$(PY) -m sbom_pipeline.cli serve --host 0.0.0.0 --port $(PORT)

docker-build:
	docker build -t aionrs/sbom-pipeline:dev .

docker-run:
	docker run --rm -p $(PORT):4007 aionrs/sbom-pipeline:dev

cli-generate:
	$(PY) -m sbom_pipeline.cli generate --source "docker:nginx:1.25" --format cyclonedx-json

cli-list:
	$(PY) -m sbom_pipeline.cli list --page 1 --page-size 20

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache .mypy_cache .coverage coverage.xml
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
