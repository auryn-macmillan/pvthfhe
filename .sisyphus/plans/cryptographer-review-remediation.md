# Cryptographer Review — Remediation Plan

**Date**: 2026-05-21  
**Source**: Discussion with Younes (May 20-21)  
**Scope**: Claims about on-chain verification gaps, proving backends, and P1/P2/P3 status

## Confirmed Claims

### C1: On-chain only sees the final proof, not per-step proofs ✅ CONFIRMED

The Noir `aggregator_final` has 15 public inputs. Most are weakly constrained:
- 5 are **dead** (never referenced in circuit body): `combined_sk_commitment_hash`, `share_verification_proof_hash`, `dkg_root`
- 5 have only `!= 0` checks: `aggregate_pk_hash`, `decrypt_nizk_hash`, `dkg_transcript_hash`, `combined_commitment_hash`, `ciphertext_hash`
- 1 has a comment stating "not constrained in-circuit": `combined_commitment_hash`
- Only 5 are meaningfully constrained: `participant_set_hash`, `committee_party_ids`, `participant_shares`, `threshold`, and plaintext return

The cryptographer's claim: "Chain only gets ~6 hashes + one compressed proof" — **accurate**.

### C2: `pvthfhe-cli verify` is a stub ✅ CONFIRMED

`main.rs:163-172` — prints "(stub)", no verification logic, "artifact serialization (TBD)".

### C3: Aggregator doesn't enforce PVSS ✅ CONFIRMED for per_aggregator binary

`per_aggregator.rs` never calls `verify_shares`. Only `full_pipeline.rs` does (line 339). A malicious aggregator could fold bad shares.

### C4: P1/P2/P3 remain OPEN ✅ CONFIRMED

Despite all gap-closure tasks being checked ✅, the fundamental cryptographic novelty remains unproven. Skeptic audit: P1=MOCK, P2=STUB, P3=MOCK.

### C5: Four proving backends used ✅ CONFIRMED

Cyclo (ring/sigma), Sonobe (Nova fold), Noir (UltraHonk), on-chain (HonkVerifier.sol). Not "Noir for the whole pipeline" as claimed.

### C6: Lattice commitments only in NIZK layer ✅ CONFIRMED

Ajtai D2 used for witness binding only. Folding (SHA-256), C7 (Poseidon), Noir (Poseidon) all use hash-based commitments.

## Remediation Tasks

### Tier 0 — Dead/unconstrained public inputs (remove attack surface)

- [ ] Remove `combined_sk_commitment_hash` from Noir `main()` signature — completely unused, dead input. Update Prover.toml writer, all test callers. → demo-e2e
- [ ] Remove `share_verification_proof_hash` from Noir `main()` signature — completely unused. → demo-e2e
- [ ] Remove `combined_commitment_hash` from Noir `main()` signature, or add a constraint. → demo-e2e
- [ ] Remove `dkg_root` from Noir `main()` signature, or add a constraint. → demo-e2e
- [ ] Fix `combined_share_hash` — currently computed in-circuit but never compared to the public input. Add `assert(computed == combined_share_hash)`. → demo-e2e
- [ ] QA: `(cd circuits && nargo test --package aggregator_final)` all pass, `just demo-e2e 16 7 1` ACCEPT

### Tier 1 — Add verify_shares to aggregator path

- [ ] Add `verify_shares` call in `per_aggregator.rs` before folding, using the existing PVSS adapter
- [ ] Add `verify_recipient_dkg_aggregation` equivalent check in per_aggregator
- [ ] Add timing output for verification phase
- [ ] QA: `just aggregator 16 7 1` completes without error

### Tier 2 — Replace the `verify` stub

- [ ] Implement `r8_verify` to deserialize proof bytes and call HonkVerifier.sol (or a mock thereof)
- [ ] Define wire format: `(compressed_proof_bytes, ciphertext_hash, plaintext_hash, public_inputs...)`
- [ ] Minimal: read proof file, print verification result
- [ ] QA: `cargo run -- verify --proof test_data/proof.hex` produces non-stub output

### Tier 3 — Document trust assumptions

- [ ] Update SECURITY.md with explicit "what's trusted, what's verified" table
- [ ] Update paper with trust boundary diagram
- [ ] Update ARCHITECTURE.md with backend inventory

### Tier 4 — Pipeline wiring

- [ ] Ensure all removal/addition tasks above work in: demo-e2e, per-node, per-aggregator
- [ ] QA: all 3 binaries at n=16 ACCEPT
