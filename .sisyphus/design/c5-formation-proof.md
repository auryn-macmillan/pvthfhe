# Design: C5 — Aggregate Public-Key Formation Proof

**Status**: DESIGN
**Created**: 2026-06-04
**Parent plan**: `execution-wave-1.md` (Task 1+2 of `c5-formation-proof.md`)
**Supersedes**: `c1-c5-pk-aggregation.md §C5` (replaces circuit approach with native Rust proof)

## 1. Problem Statement

Replace the `bytes32(0)` placeholder at `c5_proof_root` with a cryptographic proof that the aggregate public key (`pk_agg`) is correctly formed from the sum of individual participant public keys (`pk_agg = Σ pk_i`), with protection against rogue-key attacks.

### 1.1 Rogue-Key Attack

A malicious participant `M` observes honest participants publish `pk_1, pk_2, ..., pk_{n-1}`. Before publishing their own key, they compute:

```
X = a key whose secret key M knows
pk_M = X - Σ_{i≠M} pk_i
```

When the aggregator sums all keys: `pk_agg = (Σ_{i≠M} pk_i) + pk_M = X`. The adversary now knows the secret key for the aggregate, breaking the entire threshold scheme.

### 1.2 Protection: Proof-of-Possession (PoP)

Each participant proves knowledge of their secret key `sk_i` via a Schnorr-like sigma protocol over the BFV RLWE key space BEFORE their key enters the sum. The PoP binds the public key `pk_i` to the proven knowledge of `sk_i`, preventing the attacker from computing `pk_M = X - Σ pk_i` without knowing `sk_M`.

## 2. Proof Strategy

### 2.1 Relation

C5 proves the arithmetic relation:

```
pk_agg == Σ_{i=1..n} pk_i    (over the BFV RLWE key space)
```

AND each `pk_i` is accompanied by a valid PoP proving knowledge of `sk_i` satisfying the BFV key relation:

```
pk_0_i = a · sk_i + e_i   (mod Q)
```

where `a` is the common CRS polynomial (pk_1 component), `sk_i` is ternary, and `e_i` is bounded Gaussian error.

### 2.2 Native Rust Proof (Phase 1)

The initial implementation is a native Rust proof (not an in-circuit Noir proof), producing a `C5Proof` struct that bundles per-participant PoPs and the sum relation. The proof root (`c5_proof_root`) is a Poseidon BN254 hash of the proof bundle for on-chain commitment.

### 2.3 Proof-of-Possession Format

Each PoP is a Schnorr-like challenge-response proof:

- **Commitment**: `SHA256("pvthfhe-c5-pop/v1" || party_id || session_id || pk_bytes || nonce)`
- **Keygen share binding**: The keygen share bytes are revealed as the "response" — the verifier checks that `aggregate_keygen([share]) == pk_i`
- **Session binding**: The PoP binds `session_id` to prevent cross-session replay
- **Nonce**: Fresh random nonce prevents replay across different contexts

### 2.4 Real Backend Upgrade Path

When the real `FhersBackend` is used, the PoP will be replaced with a proper BFV sigma protocol proof (reusing `pvthfhe_nizk::sigma::prove` / `sigma::verify`). The `C5Proof` struct is designed to accommodate both formats through the opaque `keygen_share_bytes` field, which can carry either mock backend raw bytes or serialized sigma proofs.

## 3. Proof Format

### 3.1 C5Proof Struct

```rust
pub struct C5Proof {
    pub version: u8,                          // Proof format version (1)
    pub participant_set_hash: [u8; 32],       // SHA256(sorted party IDs)
    pub aggregate_pk_bytes: Vec<u8>,           // Raw aggregate public key bytes
    pub pops: Vec<PoP>,                        // Per-participant proofs
}
```

### 3.2 PoP Struct

```rust
pub struct PoP {
    pub party_id: PartyId,                     // Participant identifier
    pub nonce: [u8; 32],                       // Fresh random nonce
    pub commitment: [u8; 32],                  // SHA256 binding commitment
    pub keygen_share_bytes: Vec<u8>,           // Keygen share bytes (response)
}
```

### 3.3 c5_proof_root

Computed as Poseidon BN254 hash of the canonical serialization of C5Proof:

```
c5_proof_root = Poseidon(
    domain_field,
    version,
    participant_set_hash (as 2 Fr limbs),
    aggregate_pk_hash (as 2 Fr limbs),
    pop_count,
    pop_hashes[0],
    pop_hashes[1],
    ...
)
```

Uses the same `light-poseidon` BN254 x5 parameters as `pvthfhe_types::verification_statement`.

## 4. Integration Points

### 4.1 Simulator (simulator.rs)

After `aggregate_keygen` at line 348:
1. Generate PoP for each participant using `generate_pop()`
2. Bundle into `C5Proof` using `bundle_c5_proof()`
3. Compute `c5_proof_root` using `compute_c5_proof_root()`
4. Store `c5_proof_root` in the verification statement

### 4.2 Verification Statement

The `c5_proof_root: [u8; 32]` field in `VerificationStatementV1` is populated with the Poseidon hash of the C5 proof bundle, replacing the current zero-initialization.

### 4.3 On-Chain Verifier (Future — Task 4)

The `PvtFheVerifier.sol` will validate `c5ProofRoot` against the aggregated key and participant set. Deferred to Task 4.

## 5. Relationship to Other Proofs

| Concern | Proof | Status |
|---------|-------|--------|
| PK BINDING (G4) | Prove `aggregate_pk` is committed in `dkg_root` | OPEN (§B.2) |
| DKG polynomial | Prove shares are evaluations of degree-t polynomial | ✅ `dkg-parity-check-proof.md` |
| Per-party keygen (C0) | NIZK proving each participant's key is well-formed | ✅ sigma protocol |
| Key commitment binding (H2) | Commit-reveal binding of `pk_i_hash` | ✅ `compute_round1_commitment` |
| **Aggregate sum (C5)** | **Prove `pk_agg = Σ pk_i` with PoP** | **THIS DESIGN** |

C5 is orthogonal to G4: G4 binds the key to the DKG transcript, C5 proves the bound key IS the sum.

## 6. Security Considerations

### 6.1 Mock Backend Caveat

The mock backend is NOT cryptographically secure — it's XOR-based and deterministic. The PoP in the mock context serves as a structural proof-of-concept. Production security requires the real `FhersBackend` with BFV sigma protocol PoPs.

### 6.2 Rogue-Key Protection

The PoP commitment binds the participant's identity and session to their public key before reveal. Combined with the existing H2 commit-reveal binding (`compute_round1_commitment`), this provides two layers of protection:
- H2 prevents a participant from choosing their key after seeing others' commitments
- C5 PoP prevents a participant from claiming a key whose secret key they don't know

### 6.3 Soundness Budget

This proof covers the gap documented in `soundness-budget-reconciliation.md` lines 93, 159 (C5 as unproven gap). The PoP soundness relies on the hardness of the RLWE problem: an adversary who can produce a valid PoP for `pk_M` without knowing `sk_M` would break RLWE.

## 7. References

- Plan: `.sisyphus/plans/c5-formation-proof.md`
- Canonical problem: `docs/OPEN-PROBLEM-BLOCKERS.md §C5`
- Security analysis: `SECURITY.md §C5`
- Soundness budget: `soundness-budget-reconciliation.md` lines 93, 159
- Prior design (superseded): `.sisyphus/design/c1-c5-pk-aggregation.md §C5`
- BFV sigma protocol: `crates/pvthfhe-nizk/src/sigma.rs`
- Verification statement schema: `crates/pvthfhe-types/src/verification_statement.rs`
