# ARPK — build and verification entry points.
#
# Tiers (see docs/threat-model.md):
#   local  : pure Rust + wasm — arpk-core model tests, kernel PDP tests, vault native tests
#   CI     : near-workspaces sandbox, docker-compose containment, clean-room verify

CONTRACT := contracts/near-vault

.PHONY: setup verify verify-full demo fuzz judge-check clean

setup:
	@rustc --version
	@cargo --version
	@echo "wasm target:"
	@rustc --print target-list | grep -c wasm32-unknown-unknown

verify:
	cargo test -p arpk-core
	cargo test -p arpkd
	# 8 property cases: each case stands up a full contract, which is slow on Android.
	PROPTEST_CASES=8 cargo test --manifest-path $(CONTRACT)/Cargo.toml
	# 200 steps: the differential's panic path is expensive, so `make verify` keeps it a
	# smoke. `make fuzz` runs the full 10^4.
	DIFFERENTIAL_STEPS=200 PROPTEST_CASES=8 cargo test --manifest-path $(CONTRACT)/Cargo.toml --test differential
	@echo "SKIP (CI-only): Kani harnesses, near-workspaces sandbox e2e, docker containment, fuzz at volume"
	@echo "                 see .github/workflows/verify.yml and claims.json 'env' per claim"

verify-full: verify
	cargo test --release -p arpk-core
	@echo "sandbox + containment tiers run in CI (see .github/workflows/verify.yml)"

# The honesty gate: build the bundle from real artifacts, then validate it.
# CI runs this before deploying to Pages.
judge-check:
	node tools/build-site.mjs
	node tools/check-bundle.mjs site/data

# Volume tier (claim C8). Runs in CI on a real Linux runner; on Termux the release build
# alone is most of the free disk. Counts and seeds are in the CI log.
fuzz:
	PROPTEST_CASES=100000 cargo test --release -p arpk-core --test fuzz -- --nocapture
	DIFFERENTIAL_STEPS=10000 cargo test --release --manifest-path $(CONTRACT)/Cargo.toml --test differential -- --nocapture

fuzz:
	cargo test --release -p arpk-core fuzz

clean:
	cargo clean
	$(MAKE) -C $(CONTRACT) clean 2>/dev/null || true
