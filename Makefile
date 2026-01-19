.PHONY: help install install-dev test lint format typecheck clean build publish

help:  ## Display this help message
	@echo "Adversarial Code Reviewer - Development Commands"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install package in editable mode
	poetry install

install-dev:  ## Install package with development dependencies
	poetry install --with dev

test:  ## Run all tests
	poetry run pytest

test-cov:  ## Run tests with coverage report
	poetry run pytest --cov=acr --cov-report=term-missing --cov-report=html

test-unit:  ## Run unit tests only
	poetry run pytest tests/unit -v

test-integration:  ## Run integration tests only
	poetry run pytest tests/integration -v

test-e2e:  ## Run end-to-end tests only
	poetry run pytest tests/e2e -v

test-fast:  ## Run tests excluding slow tests
	poetry run pytest -m "not slow"

lint:  ## Run linter (ruff)
	poetry run ruff check .

lint-fix:  ## Run linter and auto-fix issues
	poetry run ruff check --fix .

format:  ## Format code with black
	poetry run black .

format-check:  ## Check code formatting
	poetry run black --check .

typecheck:  ## Run type checker (mypy)
	poetry run mypy acr

clean:  ## Clean build artifacts
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ .coverage htmlcov/

pre-commit:  ## Run pre-commit hooks
	poetry run pre-commit run --all-files

build:  ## Build package distribution
	poetry build

publish-test:  ## Publish to PyPI test repository
	poetry config repositories.testpypi https://test.pypi.org/legacy/
	poetry publish --repository testpypi

publish:  ## Publish to PyPI
	poetry publish

doctor:  ## Run diagnostic checks
	poetry run acr doctor

version:  ## Show version information
	@echo "ACR Version: $$(poetry version -s)"
	@echo "Python Version: $$(python --version)"
	@echo "Poetry Version: $$(poetry --version)"

init-config:  ## Initialize .acrrc.yaml configuration
	@poetry run acr init

validate-config:  ## Validate .acrrc.yaml configuration
	@poetry run acr config validate

scan-example:  ## Run example scan on tests directory
	@poetry run acr scan tests --output-format markdown

all-checks: lint format-check typecheck test  ## Run all checks (lint, format, typecheck, test)
