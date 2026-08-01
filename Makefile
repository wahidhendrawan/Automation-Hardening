.PHONY: test test-os typecheck lint security docs

test:
	python -m pytest --cov=cloud --cov-report=term-missing --cov-fail-under=60

test-os:
	bats tests/os/linux_harden.bats
	pwsh -NoProfile -Command "Invoke-Pester -Path tests/os/windows_harden.Tests.ps1 -CI"

typecheck:
	python -m mypy cloud

lint:
	python -m ruff check .
	python -m compileall -q cloud tests
	shellcheck linux/harden.sh macos/harden.sh

security:
	python -m pip_audit -r requirements.lock

docs:
	python scripts/generate_control_docs.py
