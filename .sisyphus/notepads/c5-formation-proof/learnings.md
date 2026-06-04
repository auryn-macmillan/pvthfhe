# Learnings: C5 Aggregate Public-Key Formation Proof

## 2026-06-04: Plan creation

### Key distinction: PK BINDING vs PK FORMATION

- **PK BINDING (G4)**: Proves `aggregate_pk` is committed in `dkg_root` via a Merkle-path proof in the DKG transcript. This binds the key to the transcript but the transcript could commit to an arbitrarily biased key.
- **PK FORMATION (C5)**: Proves `pk_agg == Σ pk_i` over the BFV RLWE key space. This ensures the committed key is actually the sum, preventing rogue-key attacks.

Both are needed for full security. G4 alone is insufficient without C5, and vice versa.

### Rogue-key mechanics

The attack: attacker computes `pk_M = X - Σ pk_i` where `X` is a key whose secret they know. The aggregate becomes `X`. Mitigation: each participant must prove knowledge of their secret key (PoP).

### Source file inventory

- `c5_proof_root` declared at `verification_statement.rs:70`
- `aggregate_keygen` called without proof at `simulator.rs:348`
- Solidity hardcodes `c5ProofRoot: bytes32(0)` at `PvtFheVerifier.sol:565`
- Golden fixture uses `bytes(0x80)` at `verification_statement.rs:350`

### Related but orthogonal

- `dkg-parity-check-proof.md`: dealer polynomial verification (done)
- Phase B.2 G4: Merkle-path PK binding in DKG transcript (scoped, ~3-4 days)
- C7: threshold-decryption arithmetic correctness (separate plan)
