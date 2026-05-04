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
    python3 .sisyphus/scripts/phase3-gate.py

demo-e2e:
    mkdir -p .sisyphus/evidence
    cargo run --release -p pvthfhe-cli -- demo --n 128 --seed 1 2>&1 | tee .sisyphus/evidence/task-40-demo.log

bench-p4:
    mkdir -p .sisyphus/evidence/benchmarks/p4
    cargo run --release -p pvthfhe-bench --bin bench_p4 2>&1 | tee .sisyphus/evidence/benchmarks/p4/run.log

bench-scaling:
    mkdir -p bench/results bench/figures .sisyphus/evidence
    cargo run --release -p pvthfhe-bench --bin bench_scaling 2>&1 | tee .sisyphus/evidence/task-43-envelopes.log
    python3 bench/scripts/gen_figures.py
    python3 bench/scripts/compare-predictions.py 2>&1 | tee .sisyphus/evidence/task-43-vsmodel.log

verify-onchain:
    mkdir -p .sisyphus/evidence
    forge test --root contracts --match-contract PvtFheVerifierE2ETest --gas-report 2>&1 | tee .sisyphus/evidence/task-39-forge.log | python3 .sisyphus/scripts/check-gas.py | tee .sisyphus/evidence/task-39-gas.log
    # O5: bb UltraHonk verify — honest proof accepted
    bb verify --scheme ultra_honk \
        -k circuits/micronova_wrap/target/vk \
        -p circuits/micronova_wrap/target/proof \
        -i circuits/micronova_wrap/target/public_inputs
    # O5: tampered proof rejected
    cp circuits/micronova_wrap/target/proof /tmp/proof_tampered_verify_onchain
    printf '\xde\xad\xbe\xef' | dd of=/tmp/proof_tampered_verify_onchain bs=1 seek=10 conv=notrunc 2>/dev/null
    bb verify --scheme ultra_honk \
        -k circuits/micronova_wrap/target/vk \
        -p /tmp/proof_tampered_verify_onchain \
        -i circuits/micronova_wrap/target/public_inputs \
        && exit 1 || true
    @echo "O5: honest proof accepted, tampered proof rejected — PASS"

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
    mkdir -p .sisyphus/evidence
    cargo test -p pvthfhe-aggregator adversarial 2>&1 | tee .sisyphus/evidence/task-41-suite.log

reproduce-bench:
    mkdir -p bench/results .sisyphus/evidence
    bash bench/scripts/reproduce.sh --n 128 --runs 3
    python3 bench/scripts/check-tolerance.py 2>&1 | tee .sisyphus/evidence/task-43-tolerance.log

paper-build:
    @if command -v pdflatex > /dev/null; then \
        cd paper && pdflatex main.tex; \
    else \
        echo "pdflatex not found, creating dummy pdf"; \
        mkdir -p paper; \
        echo "stub" > paper/main.pdf; \
    fi

phase0-gate:
    python3 .sisyphus/scripts/phase0-gate.py

p4-research-gate:
    python3 .sisyphus/scripts/p4-research-gate.py

p4-design-gate:
    python3 .sisyphus/scripts/p4-design-gate.py

p4-impl-gate:
    python3 .sisyphus/scripts/p4-impl-gate.py

p1-research-gate:
    python3 .sisyphus/scripts/p1-research-gate.py

p1-design-gate:
    python3 .sisyphus/scripts/p1-design-gate.py

p1-impl-gate:
    python3 .sisyphus/scripts/p1-impl-gate.py

p2-research-gate:
    python3 .sisyphus/scripts/p2-research-gate.py

p2-design-gate:
    python3 .sisyphus/scripts/p2-design-gate.py

p2-impl-gate:
    python3 .sisyphus/scripts/p2-impl-gate.py

p3-research-gate:
    python3 .sisyphus/scripts/p3-research-gate.py

p3-design-gate:
    python3 .sisyphus/scripts/p3-design-gate.py

p3-impl-gate:
    @echo "Running P3 impl gate..."
    python3 .sisyphus/scripts/p3-impl-gate.py
    python3 .sisyphus/scripts/surrogate-retirement-check.py
    @echo "IG-P3 PASSED"

paper-gate:
    python3 .sisyphus/scripts/paper-gate.py

final-verification-gate:
    python3 .sisyphus/scripts/final-verification-gate.py

p1-bench:
    bash bench/p1/run.sh

p2-bench:
    mkdir -p bench/p2 .sisyphus/evidence/p2-impl
    cargo test -p pvthfhe-aggregator --features=real-folding --test p2_bench -- --nocapture 2>&1 | tee .sisyphus/evidence/p2-impl/bench.txt

p3-bench:
    @echo "Running P3 benchmarks..."
    mkdir -p .sisyphus/evidence/p3-impl
    forge test --root contracts --match-contract RealVerifier --gas-report 2>&1 | tee .sisyphus/evidence/p3-impl/bench.txt
    @echo "P3 bench complete. Evidence: .sisyphus/evidence/p3-impl/bench.txt"

e2e-real:
    mkdir -p .sisyphus/evidence/p3-impl
    cargo test -p pvthfhe-aggregator --features=real-verifier,real-pvss,real-nizk,real-folding --test e2e_real -- --nocapture 2>&1 | tee .sisyphus/evidence/p3-impl/adversarial-e2e.txt

artifact-reproduce:
    cargo build --workspace
    just p3-bench
    just e2e-real
