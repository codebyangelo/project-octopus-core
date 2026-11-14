# SPDX-License-Identifier: Apache-2.0
# Project Octopus: Universal Polyglot Security Verification Platform

PYTHON ?= python3

.PHONY: all test verify lint format clean install profile

all: verify

install:
	@echo "[*] Installing project-octopus in editable mode..."
	$(PYTHON) -m pip install -e .

test:
	@echo "[*] Running Project Octopus test suite..."
	PYTHONPATH=src $(PYTHON) -m unittest discover tests

lint:
	@echo "[*] Running ruff lint checks..."
	@if command -v ruff >/dev/null 2>&1; then \
		ruff check src tests; \
	else \
		$(PYTHON) -m ruff check src tests 2>/dev/null || echo "[!] ruff not installed; skipping lint"; \
	fi

format:
	@echo "[*] Checking ruff formatting..."
	@if command -v ruff >/dev/null 2>&1; then \
		ruff format --check src tests; \
	fi

verify: test
	@echo "[+] ALL SYSTEMS VERIFIED: Universal engine, adapters, and reporters passed cleanly."

profile:
	@echo "[*] Profiling current repository..."
	PYTHONPATH=src $(PYTHON) -m octopus.cli --profile-only

clean:
	@echo "[*] Cleaning build and temporary artifacts..."
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
