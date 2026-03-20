.PHONY: build release check test clippy fmt clean

build:
	cd rust && cargo build

release:
	cd rust && cargo build --release

check:
	cd rust && cargo check --all-targets

test:
	cd rust && cargo test

clippy:
	cd rust && cargo clippy -- -D warnings

fmt:
	cd rust && cargo fmt

fmt-check:
	cd rust && cargo fmt -- --check

clean:
	cd rust && cargo clean

list:
	cd rust && cargo run -- list

all: fmt-check clippy test build
