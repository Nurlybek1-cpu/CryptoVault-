.PHONY: help install install-dev test test-quick test-coverage lint format type-check security-check check clean docker-build docker-run docs

help:
	@echo "CryptoVault Makefile"
	@echo "===================="
	@echo ""
	@echo "Installation:"
	@echo "  make install           - Install production dependencies"
	@echo "  make install-dev       - Install development dependencies"
	@echo ""
	@echo "Testing:"
	@echo "  make test              - Run all tests with coverage"
	@echo "  make test-quick        - Run fast smoke tests"
	@echo "  make test-coverage     - Generate HTML coverage report"
	@echo "  make test-auth         - Test auth module only"
	@echo "  make test-file-enc     - Test file encryption only"
	@echo "  make test-blockchain   - Test blockchain only"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint              - Run linter (pylint, flake8)"
	@echo "  make format            - Format code (black, isort)"
	@echo "  make type-check        - Type checking (mypy)"
	@echo "  make security-check    - Security audit (bandit)"
	@echo "  make check             - Run all checks (lint, format, type, security)"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build      - Build Docker image"
	@echo "  make docker-run        - Run Docker container"
	@echo "  make docker-dev        - Start dev environment with docker-compose"
	@echo ""
	@echo "Documentation:"
	@echo "  make docs              - Generate documentation"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean             - Clean build artifacts and cache"
	@echo "  make clean-all         - Clean everything including venv"

# Installation targets
install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt
	pip install -r requirements-dev.txt

# Testing targets
test:
	pytest tests/ -v --cov=src --cov-report=term-missing

test-quick:
	pytest tests/unit/ -v -x --tb=short

test-coverage:
	pytest tests/ --cov=src --cov-report=html
	@echo "Coverage report generated: htmlcov/index.html"

test-auth:
	pytest tests/unit/auth/ tests/integration/test_auth_flow.py -v --cov=src.auth

test-file-enc:
	pytest tests/unit/file_encryption/ tests/integration/test_file_encryption_flow.py -v --cov=src.file_encryption

test-blockchain:
	pytest tests/unit/blockchain/ tests/integration/test_blockchain_flow.py -v --cov=src.blockchain

# Code quality targets
lint:
	flake8 src/ tests/ --max-line-length=100 --exclude=__pycache__
	pylint src/ --disable=C0111,W0212

format:
	black src/ tests/
	isort src/ tests/

type-check:
	mypy src/ --ignore-missing-imports --warn-unused-ignores

security-check:
	bandit -r src/ -ll

check: lint type-check security-check
	@echo "✅ All checks passed!"

# Docker targets
docker-build:
	docker build -t cryptovault:latest .

docker-dev:
	docker-compose up -d

docker-prod:
	docker build -f Dockerfile.prod -t cryptovault:prod .
	docker run -d --name cryptovault cryptovault:prod

# Documentation
docs:
	@echo "Documentation is available in docs/ directory"
	@echo "Start with: docs/index.md"

# Cleanup targets
clean:
	find . -type f -name '*.pyc' -delete
	find . -type d -name '__pycache__' -delete
	find . -type d -name '*.egg-info' -delete
	rm -rf build/
	rm -rf dist/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	rm -rf .coverage

clean-all: clean
	rm -rf .venv/
	find . -type d -name '.venv' -delete

# Development helpers
init-db:
	python -m src.main init-db

run:
	python -m src.main

shell:
	python

freeze:
	pip freeze > requirements.txt

update-deps:
	pip list --outdated

.DEFAULT_GOAL := help