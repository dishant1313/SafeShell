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

build-ebpf:
	rustup toolchain install nightly
	rustup component add rust-src --toolchain nightly
	cd core/ebpf && cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release
	mkdir -p core/ebpf-bin
	cp core/ebpf/target/bpfel-unknown-none/release/safeshell-ebpf core/ebpf-bin/
	cd core && cargo build --release --features ebpf
