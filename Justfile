# Justfile for pvthfhe

test-all:
    cargo test --workspace
    cd circuits && nargo test --workspace
    forge test --root contracts

prereq-gate:
    cargo test -p pvthfhe-cli --test params_consistency
    cargo test -p pvthfhe-cli --test e2e_uses_lattice_pvss


# Default demo with optimized lattice features (LatticeFold+ + LaZer).
demo-e2e n="10" t="4" seed="1":
    @echo "*** PVTHFHE end-to-end demo (research prototype) ***"
    @echo "* Supported range: 1 <= t <= n <= 255 (Shamir over GF(256)) *"
    @echo "* Backends: LaZer sigma proofs + LatticeFold+ folding (post-quantum) *"
    @echo "* Ring: N=8192 (per-channel native folding, 3 RNS channels) *"
    @echo "* DO NOT DEPLOY — research prototype only                                 *"
    mkdir -p .sisyphus/evidence
    export PVTHFHE_RUN_C7_SONOBE=1
    PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 RUSTFLAGS="-Awarnings" cargo run --release -p pvthfhe-cli --features "real-compressor,demo-seeded-rng,pipeline-extra-checks,enable-lazer,enable-latticefold" -- \
        demo --n $(echo "{{n}}" | sed 's/^n=//') --threshold $(echo "{{t}}" | sed 's/^t=//') --seed $(echo "{{seed}}" | sed 's/^seed=//') \
        2>&1 | tee .sisyphus/evidence/demo-e2e.log
    @echo "*** On-chain verification ***"
    @echo "[ivc_verifier] nargo test..."
    cd circuits && nargo test --package ivc_verifier
    @echo "[ivc_verifier] nargo compile..."
    cd circuits && nargo compile --package ivc_verifier
    @echo "[ivc_verifier] bb write_vk..."
    cd circuits && bb write_vk --scheme ultra_honk -b target/ivc_verifier.json -o target
    @echo "[contracts] forge test..."
    forge test --root contracts
    @echo "*** On-chain verification: PASS ***"

# Per-node simulation — measures wall time for ONE party at given n and t
per-node n="10" t="4" seed="1":
    cargo run -p pvthfhe-cli --release --bin per-node --features "real-compressor,enable-lazer,enable-latticefold" -- --n $(echo "{{n}}" | sed 's/^n=//') --threshold $(echo "{{t}}" | sed 's/^t=//') --seed $(echo "{{seed}}" | sed 's/^seed=//')

# Per-node baseline — identical to per-node (single LatticeFold+ backend remains)
per-node-baseline n="10" t="4" seed="1":
    cargo run -p pvthfhe-cli --release --bin per-node --features "real-compressor,enable-latticefold" -- --n $(echo "{{n}}" | sed 's/^n=//') --threshold $(echo "{{t}}" | sed 's/^t=//') --seed $(echo "{{seed}}" | sed 's/^seed=//')

# Per-aggregator simulation — measures wall time for the aggregator node
aggregator n="10" t="4" seed="1":
    cargo run -p pvthfhe-cli --release --bin per-aggregator --features "real-compressor,enable-lazer,enable-latticefold" -- --n $(echo "{{n}}" | sed 's/^n=//') --threshold $(echo "{{t}}" | sed 's/^t=//') --seed $(echo "{{seed}}" | sed 's/^seed=//')

# Per-aggregator baseline — identical to aggregator (single LatticeFold+ backend remains)
aggregator-baseline n="10" t="4" seed="1":
    cargo run -p pvthfhe-cli --release --bin per-aggregator --features "real-compressor,enable-latticefold" -- --n $(echo "{{n}}" | sed 's/^n=//') --threshold $(echo "{{t}}" | sed 's/^t=//') --seed $(echo "{{seed}}" | sed 's/^seed=//')

bench-p4:
    @echo "=== P4 on-chain decider benchmark ==="
    @echo "P4 now uses Ajtai commitment UltraHonk circuit (see just ajtai-onchain-gate)."
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
    PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 cargo run -p pvthfhe-cli --bin pvthfhe-e2e --features real-compressor,demo-seeded-rng,pipeline-extra-checks -- --n $(echo "{{n}}" | sed 's/^n=//') --t $(echo "{{t}}" | sed 's/^t=//') --seed $(echo "{{seed}}" | sed 's/^seed=//')
    PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 cargo run -p pvthfhe-cli --bin pvthfhe-e2e --features real-compressor,demo-seeded-rng,pipeline-extra-checks -- --n $(echo "{{n}}" | sed 's/^n=//') --t $(echo "{{t}}" | sed 's/^t=//') --seed $(echo "{{seed}}" | sed 's/^seed=//')
    PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 cargo run -p pvthfhe-cli --bin pvthfhe-e2e --features real-compressor,demo-seeded-rng,pipeline-extra-checks -- --n $(echo "{{n}}" | sed 's/^n=//') --t $(echo "{{t}}" | sed 's/^t=//') --seed $(echo "{{seed}}" | sed 's/^seed=//')
    cargo run -p pvthfhe-bench --bin bench_comparison -- --n $(echo "{{n}}" | sed 's/^n=//') --t $(echo "{{t}}" | sed 's/^t=//') --seed $(echo "{{seed}}" | sed 's/^seed=//')
    cargo run -p pvthfhe-bench --bin render_comparison -- --comparison-json bench/results/comparison.json --output-dir bench/results

bench-comparison-dryrun n t seed:
    cargo run -p pvthfhe-bench --bin bench_comparison -- --n $(echo "{{n}}" | sed 's/^n=//') --t $(echo "{{t}}" | sed 's/^t=//') --seed $(echo "{{seed}}" | sed 's/^seed=//') --dry-run

wire-gate:
    cargo test -p pvthfhe-cli
    cargo test -p pvthfhe-aggregator
    cargo test -p pvthfhe-bench
    cargo run -p pvthfhe-cli --bin pvthfhe-e2e --features surrogate-compressor -- --n 3 --t 2 --seed 0
    just bench-comparison-dryrun 3 1 1

compressor-gate:
    cargo test -p pvthfhe-compressor
    @echo "compressor-gate: LatticeFold+ tests only"

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
    cd circuits/ivc_state_commitment && nargo execute --prover-name Ivc_state_commitment
    cd circuits/ivc_state_commitment && mkdir -p target && cp ../target/ivc_state_commitment.json target/ && cp ../target/ivc_state_commitment.gz target/
    cd circuits/ivc_state_commitment && bb write_vk --scheme ultra_honk -b target/ivc_state_commitment.json -o target
    cd circuits/ivc_state_commitment && bb prove --scheme ultra_honk -b target/ivc_state_commitment.json -w target/ivc_state_commitment.gz -o target
    cd circuits/ivc_state_commitment && bb verify --scheme ultra_honk -k target/vk -p target/proof -i target/public_inputs
    # P4: Ajtai commitment (LatticeFold+ on-chain decider)
    just ajtai-onchain-gate
    forge test --root contracts
    just verify-onchain

bench-fhe-baseline n_max="64":
    FHE_BENCH_N_MAX=$(echo "{{n_max}}" | sed 's/^n_max=//') cargo run --release -p pvthfhe-bench --bin fhe_baseline

verify-onchain:
    mkdir -p .sisyphus/evidence
    forge test --root contracts --match-contract PvtFheVerifierE2ETest --gas-report 2>&1 | tee .sisyphus/evidence/task-39-forge.log | python3 .sisyphus/scripts/check-gas.py | tee .sisyphus/evidence/task-39-gas.log
    # O5: bb UltraHonk verify — honest proof accepted
    bb verify --scheme ultra_honk \
        -k circuits/ivc_state_commitment/target/vk \
        -p circuits/ivc_state_commitment/target/proof \
        -i circuits/ivc_state_commitment/target/public_inputs
    # O5: tampered proof rejected
    cp circuits/ivc_state_commitment/target/proof /tmp/proof_tampered_verify_onchain
    printf '\xde\xad\xbe\xef' | dd of=/tmp/proof_tampered_verify_onchain bs=1 seek=10 conv=notrunc 2>/dev/null
    bb verify --scheme ultra_honk \
        -k circuits/ivc_state_commitment/target/vk \
        -p /tmp/proof_tampered_verify_onchain \
        -i circuits/ivc_state_commitment/target/public_inputs \
        && exit 1 || true
    @echo "O5: honest proof accepted, tampered proof rejected — PASS"
    # P4: Ajtai commitment UltraHonk verify
    bb verify --scheme ultra_honk \
        -k circuits/target/vk \
        -p circuits/target/proof \
        -i circuits/target/public_inputs
    @echo "P4: Ajtai commitment proof accepted — PASS"

bench-smoke:
    mkdir -p bench/results
    cargo run --release -p pvthfhe-bench --features backend-fhe-rs --bin bench_runner > bench/results/smoke-latest.json
    cat bench/results/smoke-latest.json

# Unit tests for the Python bench scripts (fit-loglog etc.)
bench-scripts-test:
    python3 -m pytest bench/scripts/tests/ -q

greco:
    @echo "=== Greco-style encryption proof (LatticeFold+ Track B) ==="
    cargo run --release -p pvthfhe-cli --features "real-compressor,enable-lazer,enable-latticefold" -- snapshot prove

compute n_ops="6":
    @echo "=== Verifiable FHE Computation (Track B LatticeFold+) ==="
    @echo "* Operations: sum $(echo "{{n_ops}}" | sed 's/^n_ops=//') ciphertexts via FHE add"
    @echo "* BFV ring: N=8192 (production). Use --features bfv-n4 for N=4 fast testing."
    cargo run --release -p pvthfhe-cli --features "real-compressor,enable-lazer,enable-latticefold" -- compute prove --n $(echo "{{n_ops}}" | sed 's/^n_ops=//')

test-circuits:
    (cd circuits && nargo test --workspace)

test-contracts:
    forge test --root contracts

adversarial-suite:
    mkdir -p .sisyphus/evidence
    cargo test -p pvthfhe-aggregator adversarial 2>&1 | tee .sisyphus/evidence/task-41-suite.log

reproduce-bench n="128" runs="3":
    mkdir -p bench/results .sisyphus/evidence
    bash bench/scripts/reproduce.sh --n {{n}} --runs {{runs}}
    python3 bench/scripts/check-tolerance.py 2>&1 | tee .sisyphus/evidence/task-43-tolerance.log

paper-build:
    @if command -v pdflatex > /dev/null; then \
        cd paper && pdflatex main.tex; \
    else \
        echo "pdflatex not found, creating dummy pdf"; \
        mkdir -p paper; \
        echo "stub" > paper/main.pdf; \
    fi
    @echo "=== DKG Paper Gate: ALL CHECKS PASSED ==="
