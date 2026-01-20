.PHONY: cargo-fix 

cargo-fix:
	@echo "Running clippy fix"
	@cargo clippy --locked --no-deps --workspace --all-targets --fix
	@echo "Running cargo fmt"
	@cargo +nightly fmt --all -- --emit files
