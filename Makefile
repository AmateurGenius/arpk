# ARPK — build and verification entry points.
#
# Tiers (see docs/threat-model.md):
#   local  : pure Rust + wasm — arpk-core model tests, kernel PDP tests, vault native tests
#   CI     : near-workspaces sandbox, docker-compose containment, clean-room verify

CONTRACT := contracts/near-vault

.PHONY: setup verify verify-full demo fuzz clean

setup:
	@rustc --version
	@cargo --version
	@echo "wasm target:"
	@rustc --print target-list | grep -c wasm32-unknown-unknown

verify:
	cargo test -p arpk-core
	cargo test -p arpkd
	cargo test --manifest-path $(CONTRACT)/Cargo.toml

verify-full: verify
	cargo test --release -p arpk-core
	@echo "sandbox + containment tiers run in CI (see .github/workflows/verify.yml)"

demo:
	@make verify

fuzz:
	cargo test --release -p arpk-core fuzz

clean:
	cargo clean
	$(MAKE) -C $(CONTRACT) clean 2>/dev/null || true
