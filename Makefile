.PHONY: build test fmt fmt-check clippy proto clean run-coord run-node ci

build:
	cargo build --workspace --all-targets

test:
	cargo test --workspace

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

proto:
	cargo build -p ferriskv-proto

clean:
	cargo clean

run-coord:
	cargo run -p ferriskv-coord

run-node:
	cargo run -p ferriskv-node

ci: fmt-check clippy test
