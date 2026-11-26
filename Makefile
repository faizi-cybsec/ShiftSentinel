# ShiftSentinel developer commands
# Usage: make test | make lint | make typecheck | make check

.PHONY: test lint typecheck check

test:
	python -m pytest -q

lint:
	ruff check .

typecheck:
	mypy shiftsentinel

check: lint typecheck test
