# Justfile for pvthfhe

test-all:
    cargo test --workspace
    cd circuits && nargo test --workspace
    forge test --root contracts

phase1-gate:
    python3 .sisyphus/scripts/phase1-gate.py

phase2-gate:
    @echo "not implemented"
    @exit 2

phase3-gate:
    @echo "not implemented"
    @exit 2

demo-e2e:
    @echo "not implemented"
    @exit 2

bench-scaling:
    @echo "not implemented"
    @exit 2

verify-onchain:
    @echo "not implemented"
    @exit 2

bench-backend-compare:
    @echo "not implemented"
    @exit 2

bench-smoke:
    mkdir -p bench/results
    cargo run --release -p pvthfhe-bench --bin bench_runner > bench/results/smoke-latest.json
    cat bench/results/smoke-latest.json

bench-folding:
    @echo "not implemented"
    @exit 2

bench-noir-rlwe:
    @echo "not implemented"
    @exit 2

bench-kzg-evm:
    @echo "not implemented"
    @exit 2

test-circuits:
    @echo "not implemented"
    @exit 2

test-contracts:
    @echo "not implemented"
    @exit 2

adversarial-suite:
    @echo "not implemented"
    @exit 2

reproduce-bench:
    @echo "not implemented"
    @exit 2
