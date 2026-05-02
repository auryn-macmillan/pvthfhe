# Justfile for pvthfhe

test-all:
    cargo test --workspace
    cd circuits && nargo test --workspace
    forge test --root contracts

phase1-gate:
    python3 .sisyphus/scripts/phase1-gate.py

phase2-gate:
    python3 .sisyphus/scripts/phase2-gate.py

phase3-gate:
    @echo "not implemented"
    @exit 2

demo-e2e:
    mkdir -p .sisyphus/evidence
    cargo run --release -p pvthfhe-cli -- demo --n 128 --seed 1 2>&1 | tee .sisyphus/evidence/task-40-demo.log

bench-scaling:
    @echo "not implemented"
    @exit 2

verify-onchain:
    mkdir -p .sisyphus/evidence
    forge test --root contracts --match-contract PvtFheVerifierE2ETest --gas-report 2>&1 | tee .sisyphus/evidence/task-39-forge.log | python3 .sisyphus/scripts/check-gas.py | tee .sisyphus/evidence/task-39-gas.log

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
    (cd circuits && nargo test --workspace)

test-contracts:
    forge test --root contracts

adversarial-suite:
    @echo "not implemented"
    @exit 2

reproduce-bench:
    @echo "not implemented"
    @exit 2
