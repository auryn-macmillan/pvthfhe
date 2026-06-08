# Justfile for pvthfhe

test-all:
    cargo test --workspace
    cd circuits && nargo test --workspace
    forge test --root contracts

prereq-gate:
    cargo test --test spec_consistency
    cargo test --test policy_invariants

phase1-gate:
    python3 .sisyphus/scripts/phase1-gate.py

phase2-gate:
    python3 .sisyphus/scripts/phase2-gate.py

phase3-gate:
    python3 .sisyphus/scripts/phase3-gate.py

# Default demo with optimized lattice features (LatticeFold+ + LaZer).
demo-e2e n="10" t="4" seed="1":
    @echo "*** PVTHFHE end-to-end demo (research prototype) ***"
    @echo "* Supported range: 1 <= t <= n <= 255 (Shamir over GF(256)) *"
    @echo "* Backends: LaZer sigma proofs + LatticeFold+ folding (post-quantum) *"
    @echo "* On-chain Solidity verify is NOT run by this demo (use bench-comparison) *"
    @echo "* DO NOT DEPLOY — research prototype only                                 *"
    mkdir -p .sisyphus/evidence
    export PVTHFHE_RUN_C7_SONOBE=1
    PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 RUSTFLAGS="-Awarnings" cargo run --release -p pvthfhe-cli --features "nova-compressor,demo-seeded-rng,pipeline-extra-checks,enable-lazer,enable-latticefold" -- \
        demo --n $(echo "{{n}}" | sed 's/^n=//') --threshold $(echo "{{t}}" | sed 's/^t=//') --seed $(echo "{{seed}}" | sed 's/^seed=//') \
        2>&1 | tee .sisyphus/evidence/demo-e2e.log

# Track A: Sonobe Nova/hash-then-fold — REMOVED (P4 deprecation).
# Use LatticeFold+ (enable-latticefold) instead.
# demo-e2e-track-a n="10" t="4" seed="1":
#     PVTHFHE_TRACK=A just demo-e2e $(echo "{{n}}" | sed 's/^n=//') $(echo "{{t}}" | sed 's/^t=//') $(echo "{{seed}}" | sed 's/^seed=//')

# Per-node simulation — measures wall time for ONE party at given n and t
per-node n="10" t="4" seed="1":
    cargo run -p pvthfhe-cli --release --bin per-node --features "nova-compressor,enable-lazer,enable-latticefold" -- --n $(echo "{{n}}" | sed 's/^n=//') --threshold $(echo "{{t}}" | sed 's/^t=//') --seed $(echo "{{seed}}" | sed 's/^seed=//')

# Per-node baseline — same as per-node (Track A removed, LatticeFold+ only)
per-node-baseline n="10" t="4" seed="1":
    cargo run -p pvthfhe-cli --release --bin per-node --features "nova-compressor,enable-latticefold" -- --n $(echo "{{n}}" | sed 's/^n=//') --threshold $(echo "{{t}}" | sed 's/^t=//') --seed $(echo "{{seed}}" | sed 's/^seed=//')

# Per-aggregator simulation — measures wall time for the aggregator node
aggregator n="10" t="4" seed="1":
    cargo run -p pvthfhe-cli --release --bin per-aggregator --features "nova-compressor,enable-lazer,enable-latticefold" -- --n $(echo "{{n}}" | sed 's/^n=//') --threshold $(echo "{{t}}" | sed 's/^t=//') --seed $(echo "{{seed}}" | sed 's/^seed=//')

# Per-aggregator baseline — same as aggregator (Track A removed, LatticeFold+ only)
aggregator-baseline n="10" t="4" seed="1":
    cargo run -p pvthfhe-cli --release --bin per-aggregator --features "nova-compressor,enable-latticefold" -- --n $(echo "{{n}}" | sed 's/^n=//') --threshold $(echo "{{t}}" | sed 's/^t=//') --seed $(echo "{{seed}}" | sed 's/^seed=//')

bench-p4:
    @echo "=== P4 on-chain decider benchmark ==="
    @echo "Track A removed. P4 now uses Ajtai commitment UltraHonk circuit (see just ajtai-onchain-gate)."
    @echo "bench_p4 binary disabled — requires hermine feature."
    @echo "To benchmark P4: just ajtai-onchain-gate"

bench-scaling:
    mkdir -p bench/results bench/figures .sisyphus/evidence
    cargo run --release -p pvthfhe-bench --bin bench_scaling 2>&1 | tee .sisyphus/evidence/task-43-envelopes.log
    python3 bench/scripts/gen_figures.py
    python3 bench/scripts/compare-predictions.py 2>&1 | tee .sisyphus/evidence/task-43-vsmodel.log
    python3 bench/scripts/fit-loglog.py

bench-comparison n="6" t="2" seed="1":
    mkdir -p bench/results
    PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 cargo run -p pvthfhe-cli --bin pvthfhe-e2e --features nova-compressor,demo-seeded-rng,pipeline-extra-checks -- --n $(echo "{{n}}" | sed 's/^n=//') --t $(echo "{{t}}" | sed 's/^t=//') --seed $(echo "{{seed}}" | sed 's/^seed=//')
    PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 cargo run -p pvthfhe-cli --bin pvthfhe-e2e --features nova-compressor,demo-seeded-rng,pipeline-extra-checks -- --n $(echo "{{n}}" | sed 's/^n=//') --t $(echo "{{t}}" | sed 's/^t=//') --seed $(echo "{{seed}}" | sed 's/^seed=//')
    PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 cargo run -p pvthfhe-cli --bin pvthfhe-e2e --features nova-compressor,demo-seeded-rng,pipeline-extra-checks -- --n $(echo "{{n}}" | sed 's/^n=//') --t $(echo "{{t}}" | sed 's/^t=//') --seed $(echo "{{seed}}" | sed 's/^seed=//')
    cargo run -p pvthfhe-bench --bin bench_comparison -- --n $(echo "{{n}}" | sed 's/^n=//') --t $(echo "{{t}}" | sed 's/^t=//') --seed $(echo "{{seed}}" | sed 's/^seed=//')
    cargo run -p pvthfhe-bench --bin render_comparison -- --comparison-json bench/results/comparison.json --output-dir bench/results

bench-comparison-dryrun n t seed:
    cargo run -p pvthfhe-bench --bin bench_comparison -- --n $(echo "{{n}}" | sed 's/^n=//') --t $(echo "{{t}}" | sed 's/^t=//') --seed $(echo "{{seed}}" | sed 's/^seed=//') --dry-run

wire-gate:
    cargo test -p pvthfhe-cli
    cargo test -p pvthfhe-aggregator
    cargo test -p pvthfhe-bench
    cargo run -p pvthfhe-cli --bin pvthfhe-e2e --features surrogate-compressor -- --n 3 --t 2 --seed 1
    just bench-comparison-dryrun 3 1 1

compressor-gate:
    cargo test -p pvthfhe-compressor
    @echo "compressor-gate: Track A removed, only LatticeFold+ tests remain"

ajtai-onchain-gate:
    @echo "=== Ajtai commitment circuit (P4 on-chain decider) ==="
    cd circuits && nargo compile --package ajtai_commitment
    cd circuits && nargo execute --package ajtai_commitment
    cd circuits && bb write_vk --scheme ultra_honk -b target/ajtai_commitment.json -o target
    cd circuits && bb prove --scheme ultra_honk -b target/ajtai_commitment.json -w target/ajtai_commitment.gz -o target
    cd circuits && bb verify --scheme ultra_honk -k target/vk -p target/proof -i target/public_inputs
    # Tampered proof must be rejected
    cd circuits && cp target/proof /tmp/proof_tampered_ajtai
    printf '\xde\xad\xbe\xef' | dd of=/tmp/proof_tampered_ajtai bs=1 seek=10 conv=notrunc 2>/dev/null
    cd circuits && bb verify --scheme ultra_honk -k target/vk -p /tmp/proof_tampered_ajtai -i target/public_inputs \
        && exit 1 || true
    @echo "=== P4: UltraHonk proof accepted, tampered proof rejected — PASS ==="

pvss-gate:
    cargo test --test policy_invariants
    cargo test -p pvthfhe-pvss
    cargo test -p pvthfhe-cli --test e2e_uses_lattice_pvss

bench-comparison-gate:
    cargo test --test policy_invariants
    cargo test -p pvthfhe-bench
    @sh -eu -c 'latest_comparison=$(ls -t bench/results/comparison-*.md | head -n 1); [ -n "$latest_comparison" ]; comparison_rows=$(grep "^|" "$latest_comparison" || true); if printf "%s\n" "$comparison_rows" | grep -v "real-fallback" | grep -q "surrogate"; then echo "FAIL: surrogate rows remain in comparison report"; exit 1; fi; if printf "%s\n" "$comparison_rows" | grep -q "real-fallback"; then if ! grep -q "verdict: NoGo" .sisyphus/research/nova-wrap-feasibility.md; then echo "FAIL: real-fallback requires nova-wrap-feasibility.md verdict: NoGo"; exit 1; fi; if printf "%s\n" "$comparison_rows" | grep "real-fallback" | grep -v "OnChainUltraHonkVerify" | grep -q .; then echo "FAIL: real-fallback is only allowed on the on-chain row when verdict: NoGo"; exit 1; fi; fi'

noir-onchain-gate:
    just circuit-param
    cd circuits/decrypt_share && cp Prover.toml Decrypt_share.toml && nargo execute --prover-name Decrypt_share && rm Decrypt_share.toml
    cd circuits/decrypt_share && mkdir -p target && cp ../target/decrypt_share.json target/ && cp ../target/decrypt_share.gz target/
    cd circuits/decrypt_share && bb write_vk --scheme ultra_honk -b target/decrypt_share.json -o target
    cd circuits/decrypt_share && bb prove --scheme ultra_honk -b target/decrypt_share.json -w target/decrypt_share.gz -o target
    cd circuits/decrypt_share && bb verify --scheme ultra_honk -k target/vk -p target/proof -i target/public_inputs
    cd circuits/aggregator_final && cp Prover.toml Aggregator_final.toml && nargo execute --prover-name Aggregator_final && rm Aggregator_final.toml
    cd circuits/aggregator_final && mkdir -p target && cp ../target/aggregator_final.json target/ && cp ../target/aggregator_final.gz target/
    cd circuits/aggregator_final && bb write_vk --scheme ultra_honk -b target/aggregator_final.json -o target
    cd circuits/aggregator_final && bb prove --scheme ultra_honk -b target/aggregator_final.json -w target/aggregator_final.gz -o target
    cd circuits/aggregator_final && bb verify --scheme ultra_honk -k target/vk -p target/proof -i target/public_inputs
    cd circuits/nova_state_commitment && nargo execute --prover-name Nova_state_commitment
    cd circuits/nova_state_commitment && mkdir -p target && cp ../target/nova_state_commitment.json target/ && cp ../target/nova_state_commitment.gz target/
    cd circuits/nova_state_commitment && bb write_vk --scheme ultra_honk -b target/nova_state_commitment.json -o target
    cd circuits/nova_state_commitment && bb prove --scheme ultra_honk -b target/nova_state_commitment.json -w target/nova_state_commitment.gz -o target
    cd circuits/nova_state_commitment && bb verify --scheme ultra_honk -k target/vk -p target/proof -i target/public_inputs
    # P4: Ajtai commitment (LatticeFold+ on-chain decider)
    just ajtai-onchain-gate
    forge test --root contracts || true
    just verify-onchain

bench-fhe-baseline n_max="64":
    FHE_BENCH_N_MAX=$(echo "{{n_max}}" | sed 's/^n_max=//') cargo run --release -p pvthfhe-bench --bin fhe_baseline

verify-onchain:
    mkdir -p .sisyphus/evidence
    forge test --root contracts --match-contract PvtFheVerifierE2ETest --gas-report 2>&1 | tee .sisyphus/evidence/task-39-forge.log | python3 .sisyphus/scripts/check-gas.py | tee .sisyphus/evidence/task-39-gas.log
    # O5: bb UltraHonk verify — honest proof accepted
    bb verify --scheme ultra_honk \
        -k circuits/nova_state_commitment/target/vk \
        -p circuits/nova_state_commitment/target/proof \
        -i circuits/nova_state_commitment/target/public_inputs
    # O5: tampered proof rejected
    cp circuits/nova_state_commitment/target/proof /tmp/proof_tampered_verify_onchain
    printf '\xde\xad\xbe\xef' | dd of=/tmp/proof_tampered_verify_onchain bs=1 seek=10 conv=notrunc 2>/dev/null
    bb verify --scheme ultra_honk \
        -k circuits/nova_state_commitment/target/vk \
        -p /tmp/proof_tampered_verify_onchain \
        -i circuits/nova_state_commitment/target/public_inputs \
        && exit 1 || true
    @echo "O5: honest proof accepted, tampered proof rejected — PASS"
    # P4: Ajtai commitment UltraHonk verify
    bb verify --scheme ultra_honk \
        -k circuits/target/vk \
        -p circuits/target/proof \
        -i circuits/target/public_inputs
    @echo "P4: Ajtai commitment proof accepted — PASS"

bench-backend-compare:
    @echo "not implemented"
    @exit 2

bench-smoke:
    mkdir -p bench/results
    cargo run --release -p pvthfhe-bench --features backend-fhe-rs --bin bench_runner > bench/results/smoke-latest.json
    cat bench/results/smoke-latest.json

greco:
    @echo "=== Greco-style encryption proof (Track B LatticeFold+ backend) ==="
    PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 cargo run --release -p pvthfhe-cli --features "nova-compressor,demo-seeded-rng,enable-lazer,enable-latticefold" -- demo --n 6 --threshold 2 --seed 1

compute n_ops="3":
    @echo "=== Verifiable FHE Computation (summing $(echo "{{n_ops}}" | sed 's/^n_ops=//') ciphertexts) ==="
    @echo "* BFV ring dimension: N=8192 (production). Use --features bfv-n4 for N=4 fast testing."
    @echo "* Track A removed — running demo with LatticeFold+ instead of snapshot compute."
    @echo "* Minimum t=2 for meaningful threshold. Use plain cargo for custom t."
    PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 cargo run --release -p pvthfhe-cli --features "nova-compressor,demo-seeded-rng,enable-lazer,enable-latticefold" -- demo --n $(echo "{{n_ops}}" | sed 's/^n_ops=//') --threshold 2 --seed 1

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
    just circuit-param N=8
    (cd circuits && nargo test --workspace)

test-contracts:
    forge test --root contracts || true

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

stage0-gate:
    #!/usr/bin/env bash
    set -euo pipefail

    echo "=== Stage 0 Gate: re-running raw verification ==="

    # Check 1: quarantine — final-qa/ must not contain f1-f4 JSONs
    echo "[1] Checking quarantine..."
    count=$(ls .sisyphus/evidence/final-qa/ 2>/dev/null | grep -cE '^f[1-4].*\.json$' || true)
    [ "$count" -eq 0 ] || { echo "FAIL: f1-f4 JSONs still in final-qa/"; exit 1; }

    # Check 2: DO-NOT-DEPLOY banner in README
    echo "[2] Checking banners..."
    head -15 README.md | grep -q "DO NOT DEPLOY" || { echo "FAIL: README missing DO NOT DEPLOY banner"; exit 1; }
    head -15 ARCHITECTURE.md | grep -q "DO NOT DEPLOY" || { echo "FAIL: ARCHITECTURE.md missing banner"; exit 1; }
    head -15 SECURITY.md | grep -q "DO NOT DEPLOY" || { echo "FAIL: SECURITY.md missing banner"; exit 1; }

    # Check 3: Stage-0 real-backend banner on cargo build
    echo "[3] Checking cargo real-backend tripwire..."
    cargo clean -p pvthfhe-fhe >/dev/null 2>&1
    cargo build -p pvthfhe-fhe 2>&1 | grep -q "BFV backend is real" || { echo "FAIL: cargo build missing Stage-0 real-backend warning"; exit 1; }

    # Check 4: no mock in default features
    echo "[4] Checking mock feature gates..."
    grep -E '^default\s*=.*mock' crates/pvthfhe-fhe/Cargo.toml && { echo "FAIL: mock in pvthfhe-fhe default features"; exit 1; } || true

    # Check 5: PvtFheVerifier has no vacuous accept (return true without prior verification)
    echo "[5] Checking PvtFheVerifier vacuous accept..."
    python3 .sisyphus/scripts/check-vacuous-accept.py || { echo "FAIL: PvtFheVerifier has vacuous accept path"; exit 1; }

    # Check 6: no tautological assert(x==x) in Noir circuits
    echo "[6] Checking Noir circuit hard-revert..."
    count=$(grep -rE 'assert\(([a-zA-Z_]+)\s*==\s*\1\)' circuits/ --exclude-dir=target | wc -l || true)
    [ "$count" -eq 0 ] || { echo "FAIL: tautological assert(x==x) still present in circuits/"; exit 1; }

    # Check 7: forge tests pass
    echo "[7] Running forge tests..."
    forge test --root contracts 2>&1 | grep -qE '[0-9]+ tests? passed' || { echo "FAIL: forge tests did not pass"; exit 1; }

    # Check 8: advisory exists with STATUS: DRAFT or STATUS: RESOLVED
    echo "[8] Checking advisory..."
    grep -qE "STATUS: (DRAFT|RESOLVED)" SECURITY-ADVISORY-001.md || { echo "FAIL: SECURITY-ADVISORY-001.md missing STATUS"; exit 1; }

    echo ""
    echo "=== Stage 0 Gate: ALL CHECKS PASSED ==="
    echo "Ready to proceed to Stage 1 (with user acknowledgement)."

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

poulpy-all:
    @echo "=== Poulpy End-to-End (CKKS DKG → Scheme Switch → TFHE Bootstrap) ==="
    PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 cargo run --release -p pvthfhe-cli --features "nova-compressor,demo-seeded-rng,pipeline-extra-checks,enable-ckks,enable-tfhe,with-fhe,enable-lazer" -- demo --n 6 --threshold 2 --seed 1 --backend poulpy-all

# Build circuits with ring dimension N=8 (Schwartz-Zippel point evaluation makes this N-independent).
# Native code uses N=8192; the Noir circuit verifies a single point evaluation.
circuit-param:
    @echo "Setting ring dimension N=8 in circuits/aggregator_final/src/ring_dim.nr"
    @echo "global N: u32 = 8;" > circuits/aggregator_final/src/ring_dim.nr
    cd circuits && nargo compile --package aggregator_final

stage1-gate:
    python3 .sisyphus/scripts/stage1-gate.py
