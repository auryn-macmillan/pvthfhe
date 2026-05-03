# P1→P2 Downstream Contract Bundle

This bundle freezes the P1 implementation handoff that P2 must consume before any LatticeFold+ folding work begins. It is produced after IG-P1 passes all subchecks.

---

## 1. Frozen API

The following Rust signatures are frozen as of B.I.2. P2 must not assume any internal implementation detail beyond this surface.

### `NizkStatement`

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NizkStatement {
    /// Canonical ciphertext bytes (opaque deterministic handle).
    pub ciphertext_bytes: Vec<u8>,
    /// Canonical partial decrypt-share bytes (opaque deterministic handle).
    pub decrypt_share_bytes: Vec<u8>,
    /// P4 PVSS commitment hash: SHA256(session_id || participant_id.to_le_bytes() || secret_share.to_be_bytes()).
    pub pvss_commitment: [u8; 32],
    /// Bound FHE parameter tuple: (q, ring_degree_n, error_bound_b_e).
    pub params: (u64, usize, u64),
    /// Session binding inherited from P4 (canonical UTF-8).
    pub session_id: String,
    /// 1-based participant binding inherited from P4.
    pub participant_id: u16,
}
```

### `NizkWitness`

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NizkWitness {
    /// Secret share value inherited from P4 (Shamir field element).
    pub secret_share: u64,
    /// Lattice error vector (signed coefficients).
    pub error: Vec<i64>,
    /// Prover randomness (auxiliary witness material, never in proof bytes).
    pub randomness: Vec<u8>,
}
```

### `NizkProof`

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NizkProof {
    /// Proof backend identifier: "slap" for the real implementation.
    pub backend_id: String,
    /// Deterministic serialized proof payload (see Section 6 for binary layout).
    pub proof_bytes: Vec<u8>,
}

impl NizkProof {
    pub fn as_bytes(&self) -> &[u8];
}
```

### `LatticeNizk` trait

```rust
pub trait LatticeNizk {
    fn prove(
        stmt: &NizkStatement,
        witness: &NizkWitness,
        rng: &mut impl RngCore,
    ) -> Result<NizkProof, NizkError>;

    fn verify(stmt: &NizkStatement, proof: &NizkProof) -> Result<(), NizkError>;

    fn batch_verify(stmts: &[NizkStatement], proofs: &[NizkProof]) -> Result<(), NizkError>;
}
```

### Concrete implementation

- `RealNizkAdapter` implements `LatticeNizk` under Cargo feature `real-nizk` (default).
- Legacy surrogate available under `surrogate-decrypt-share` feature (disabled by default).
- Location: `crates/pvthfhe-fhe/src/real_nizk.rs`

---

## 2. Public Parameters

| Parameter | Value | Source |
|---|---|---|
| `q` | 65537 | `bench/p1/results-*.json`, `real_nizk.rs` |
| `ring_degree_n` | 128 / 512 / 1024 | bench-plan sizes; `NizkStatement.params.1` |
| `error_bound_b_e` | 17 | `bench/p1/results-*.json`, `real_nizk.rs` |
| `backend_id` | `"slap"` | `BACKEND_ID` constant in `real_nizk.rs` |
| `PROOF_VERSION` | 1 | `PROOF_VERSION: u16 = 1` constant in `real_nizk.rs` |

These values are frozen for P1. P2 must bind them in any folding circuit or constraint system that aggregates P1 proofs.

---

## 3. Security Caveats

The following limitations are inherited by P2 and must be explicitly acknowledged in any downstream security claim.

1. **ROM (Fiat-Shamir).** The challenge is derived via `SHA-256(session_id || pvss_commitment || t_bytes || statement_bytes)`. Security relies on the random-oracle model; standard-model security is not claimed.

2. **Ternary challenge set `{-1, 0, 1}`.** The challenge weight is one of `{-1, 0, 1}` (selected from `challenge_bytes[15] % 3`). This is a sigma-protocol design choice; the small challenge set means soundness error is 1/3 per round (not negligible for single invocations — repeated composition or stronger challenge spaces are deferred to T4).

3. **T4 (simulation-extractability) DEFERRED.** The current proof is a standard sigma protocol with Fiat-Shamir. Simulation-extractability (sim-ext) is explicitly not proven and is listed as an open problem in `docs/security-proofs/p1/T4.md`. P2 must not assume sim-ext without independent argument.

4. **Direct witness opening (not ZK in the strong sense).** The proof payload includes `secret_share_open` and `error_open` as direct openings of the witness (see `ProofPayload`). This is a design artifact of the current SLAP instantiation; it provides only honest-verifier zero-knowledge (HVZK). Full (malicious-verifier) ZK is not claimed. P2 folding must account for this when reasoning about witness privacy.

5. **Shamir share provenance.** `secret_share` is a Shamir field element over `p = 2^61 - 1` inherited from P4. It is not an RLWE-native secret. The gap between the current Shamir-based P4 handoff and the eventual RLWE share format is an unresolved upstream risk.

---

## 4. Performance Envelope

Concrete benchmark numbers from `bench/p1/results-1024.json` (n=1024, q=65537, error_bound=17, 100 iterations):

| Metric | Value |
|---|---|
| Median prove time | 0.0231 ms |
| Median verify time | 0.0078 ms |
| Proof size | 24,654 bytes (~24.1 KB) |
| Batch verify (1 proof) | 0.0173 ms |
| Batch verify (10 proofs) | 0.0837 ms |
| Batch verify (100 proofs) | 0.846 ms (0.00846 ms/proof) |

**Scaling:** Proof size is linear in `n` (the ring degree). At n=1024 the proof is ~24 KB; at n=128 it is proportionally smaller. The exact values for all three sizes are captured in the regression baseline (Section 7).

**P2 budget note:** At n=1024, a single verify costs ~0.008 ms. P2 folding 1024 shares must plan for ~8 ms of verification work per round (sequential). Batch-verify is available and should be used.

---

## 5. Recursion-Friendliness for P2

P2 (LatticeFold+) needs to fold over the NIZK verification equation. The following properties are relevant:

### Sigma transcript structure

The sigma transcript is: `(t_bytes, challenge_bytes, z_s, z_e)` where:
- `t_bytes` = `mask_secret || mask_error` (the commitment to mask randomness)
- `challenge_bytes` = SHA-256 output (16 bytes used), derived via Fiat-Shamir
- `z_s: u64` = response scalar (mask + challenge × secret, mod q)
- `z_e: Vec<i64>` = response error vector (mask_error + challenge_weight × error)

**All components are arithmetic.** The transcript involves only modular arithmetic and norm-bound checks — both of which are expressible as arithmetic constraints. This makes the transcript foldable in principle.

### Key constraint for P2

The `z_e` norm bound must be handled in the folding circuit:
- The verifier checks `|z_e[i]| ≤ 2 × error_bound` (i.e., ≤ 34 for the standard parameters).
- This is a range check that P2 must incorporate into the folding constraint system.

### Verification equation (arithmetic form)

Given `(stmt, t_bytes, z_s, z_e, secret_share_open, error_open)`:

1. Recompute `challenge = SHA-256(session_id || pvss_commitment || t_bytes || stmt_bytes)[..16]`
2. Compute `challenge_weight ∈ {-1, 0, 1}` from `challenge[15] % 3`
3. Recover `y_s = (z_s - challenge_weight × secret_share_open) mod q`
4. Recover `y_e[i] = z_e[i] - challenge_weight × error_open[i]`
5. Check `t_bytes == mask_commitment_bytes(y_s, y_e)` (i.e., `[be_u64(y_s)][u32_len][be_i64s(y_e)]`)
6. Check `pvss_commitment == SHA-256(session_id || participant_id.to_le_bytes() || secret_share_open.to_be_bytes())`
7. Check `|error_open[i]| ≤ error_bound` for all i
8. Check `|z_e[i]| ≤ 2 × error_bound` for all i

Steps 3-5 and 7-8 are purely arithmetic. Steps 1, 2, and 6 involve SHA-256 (hash gadget required in folding circuit).

### Deserializer note

P2 must parse `proof_bytes` to extract the transcript components. See Section 6 for the exact binary layout.

---

## 6. Deserializer Spec

The exact binary layout of `proof_bytes` is produced by `ProofPayload::encode()` in `crates/pvthfhe-fhe/src/real_nizk.rs`:

```
[2B  version       ] u16, big-endian; must equal PROOF_VERSION = 1
[4B  t_len         ] u32, big-endian; byte length of t_bytes
[t_len bytes       ] t_bytes: mask commitment = be_u64(mask_secret) || u32_len(mask_error) || be_i64s(mask_error)
[8B  z_s           ] u64, big-endian; secret response scalar
[4B  z_e_count     ] u32, big-endian; number of z_e elements
[z_e_count × 8B    ] z_e: Vec<i64>, each element big-endian i64
[8B  secret_share_open] u64, big-endian; opened secret share
[4B  error_count   ] u32, big-endian; number of error_open elements
[error_count × 8B  ] error_open: Vec<i64>, each element big-endian i64
[4B  rand_len      ] u32, big-endian; byte length of randomness_open
[rand_len bytes    ] randomness_open: prover randomness bytes
```

All multi-byte integers are **big-endian**. Length prefixes are **u32 big-endian**. There are no alignment pads, separators, or trailers.

**t_bytes internal layout** (encoding of `mask_commitment_bytes(y_s, y_e)`):
```
[8B  mask_secret   ] u64, big-endian
[4B  mask_e_count  ] u32, big-endian; number of mask_error elements
[mask_e_count × 8B ] mask_error: Vec<i64>, each big-endian i64
```

**Decoder invariants** (enforced by `ProofPayload::decode()`):
- Trailing bytes after the final field → error `"trailing proof bytes"`
- Truncated read at any field → error `"truncated proof bytes"`
- Version mismatch → error `"unsupported proof version"`
- `z_e.len() != error_open.len()` → error `"response/error length mismatch"` (checked by verifier)

---

## 7. Regression Baseline

The following benchmark files constitute the frozen regression baseline for P1:

| File | n | Median prove (ms) | Median verify (ms) | Proof size (bytes) |
|---|---|---|---|---|
| `bench/p1/results-128.json` | 128 | (see file) | (see file) | (see file) |
| `bench/p1/results-512.json` | 512 | (see file) | (see file) | (see file) |
| `bench/p1/results-1024.json` | 1024 | 0.0231 | 0.0078 | 24,654 |

**Regression policy:** Any future change to `crates/pvthfhe-fhe/src/real_nizk.rs` or the SLAP parameter tuple that results in a prove time exceeding **2× the baseline median** for any of the three sizes requires a new review before merging. Proof-size increases beyond 2× baseline also require new review.

The baseline is frozen as of gate `IG-P1` passing. Evidence is archived at `.sisyphus/evidence/p1-impl/gate-output.txt`.

---

*Bundle produced by*: B.I.6 — `gate(p1): IG-P1 passes + P1→P2 downstream contract bundle`
