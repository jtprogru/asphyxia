.DEFAULT_GOAL := help

# Pass extra arguments to `make run`, e.g. `make run ARGS="ps -t example.com -s 80,443"`
ARGS ?=

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the project (debug)
	cargo build --locked

.PHONY: release
release: ## Build an optimized release binary
	cargo build --locked --release

.PHONY: run
run: ## Run the binary; pass args via ARGS="..."
	cargo run -- $(ARGS)

.PHONY: test
test: ## Run unit and doc tests
	cargo test --locked

.PHONY: fmt
fmt: ## Format the code
	cargo fmt --all

.PHONY: fmt-check
fmt-check: ## Check formatting without modifying files
	cargo fmt --all -- --check

.PHONY: clippy
clippy: ## Lint with Clippy (warnings denied)
	cargo clippy --all-targets -- -D warnings

.PHONY: lint
lint: fmt-check clippy ## Run format check and Clippy

.PHONY: check
check: ## Type-check without producing a binary
	cargo check --all-targets

.PHONY: doc
doc: ## Build and open the API documentation
	cargo doc --no-deps --open

.PHONY: ci
ci: fmt-check clippy build test ## Run the full local CI pipeline (mirrors GitHub Actions)

.PHONY: clean
clean: ## Remove build artifacts
	cargo clean
