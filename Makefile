.PHONY: build test fmt fmt-check clippy proto clean run-coord run-node ci fuzz fuzz-build

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

fuzz-build:
	cargo +nightly fuzz build

# One short pass over every target, seeded from the committed corpus. Matches
# what CI runs on a pull request; the nightly workflow uses a longer budget.
fuzz:
	@for t in key_decode key_roundtrip value_decode wal_frame node_config; do \
		echo "=== fuzzing $$t ==="; \
		mkdir -p fuzz/corpus/$$t; \
		cargo +nightly fuzz run $$t fuzz/corpus/$$t fuzz/seeds/$$t \
			-- -max_total_time=$${SECONDS_PER_TARGET:-60} -print_final_stats=1 || exit 1; \
	done

ci: fmt-check clippy test
