.PHONY: setup build test lint fmt clean

setup:
	bash scripts/setup_env.sh

build:
	cd core && cargo build --release

test:
	.venv/bin/python -m pytest tests/ -v

lint:
	.venv/bin/python -m ruff check safeshell/ tests/
	cd core && cargo clippy -- -D warnings

fmt:
	.venv/bin/python -m ruff format safeshell/ tests/
	cd core && cargo fmt

clean:
	rm -rf core/target .safeshell __pycache__
