# P2 Frozen Interface Spec (Folding API)

This document freezes the P2 folding boundary that consumes the frozen P1 `NizkStatement`/`NizkProof` handoff and exports a backend-agnostic accumulator/final-proof interface for P3. The public API binds the inherited `(q, N, B_e)` tuple, ordered fold history, and session metadata without exposing backend-specific gadgets, field types, or accumulator internals.

## Statement Type

```rust
FoldStatement {
    nizk_statement: NizkStatement,  // inherited from P1 (frozen)
    fold_index: u64,                // 1-based fold step
    session_id: String,             // inherits from NizkStatement
    params: (u64, usize, u64),      // (q, N, B_e) — must match inner NizkStatement.params
}
```

Validity rules:

- `fold_index` is 1-based and strictly identifies the statement position in the ordered fold transcript.
- `session_id` MUST equal `nizk_statement.session_id`.
- `params` MUST equal `nizk_statement.params` and MUST remain fixed across the entire fold session.
- `FoldStatement` is semantic input only: callers provide the inherited P1 statement plus fold metadata, while backend adapters handle any internal encoding required by the active folding system.
- Canonical `current_fold_statement_bytes` for hash-chaining are the deterministic serialization of `(nizk_statement, fold_index, session_id, params)` in that field order using the already-frozen P1 statement encoding for `nizk_statement`, UTF-8 bytes for `session_id`, and fixed-width integer encodings for numeric fields.

## Witness Type

```rust
FoldWitness {
    nizk_proof: NizkProof,          // inner P1 proof (frozen)
    fold_randomness: Vec<u8>,       // fresh per-fold randomness (not reused)
}
```

Validity rules:

- `nizk_proof` is the opaque frozen P1 proof blob; P2 may parse it internally, but no proof-system-specific transcript components appear in this public interface.
- `fold_randomness` MUST be freshly sampled for each `fold` invocation and MUST NOT be reused across fold steps.
- Fresh fold randomness is required to support the projected transcript privacy target from P2-T3 even when the inner P1 proof format contains audit-only witness openings.

## Accumulator Type

```rust
FoldAccumulator {
    acc_commitment: Vec<u8>,        // serialized accumulator commitment (lattice or non-lattice, backend-specific)
    fold_depth: u64,                // number of successful folds applied
    session_id: String,             // session binding (from NizkStatement)
    params: (u64, usize, u64),      // frozen FHE params — MUST be consistent across all folds
    statement_hash_chain: [u8; 32], // SHA-256(prev_hash || current_fold_statement_bytes), initialized to [0u8; 32]
}
```

State rules:

- `acc_commitment` is an opaque serialized backend artifact; its length and internal format are backend-defined, but its bytes MUST bind the same fold history represented by `statement_hash_chain`.
- `fold_depth` counts only successful fold applications. The empty accumulator has `fold_depth = 0` and `statement_hash_chain = [0u8; 32]`.
- `session_id` MUST stay constant for the lifetime of the accumulator and MUST match every folded statement.
- `params` MUST stay constant for the lifetime of the accumulator and MUST equal every folded statement's `params` tuple.
- On each successful fold transition, `statement_hash_chain` advances as `SHA-256(prev_hash || current_fold_statement_bytes)`.
- `verify_acc` MUST reject any accumulator whose visible metadata (`fold_depth`, `session_id`, `params`, `statement_hash_chain`) is inconsistent with the backend commitment semantics.

## Folding API

```rust
pub trait FoldingScheme {
    /// Accumulate one P1 NIZK proof into the running accumulator.
    fn fold(acc: &FoldAccumulator, witness: &FoldWitness, stmt: &FoldStatement) -> Result<FoldAccumulator, FoldError>;

    /// Verify that the accumulator is well-formed and binds a valid fold history.
    fn verify_acc(acc: &FoldAccumulator, expected_params: &(u64, usize, u64)) -> Result<(), FoldError>;

    /// Finalize: produce the terminal proof blob for P3 consumption.
    fn finalize(acc: &FoldAccumulator) -> Result<FinalProof, FoldError>;
}
```

```rust
pub struct FinalProof {
    pub proof_bytes: Vec<u8>,    // ≤14KB target (P2-T5)
    pub public_inputs: P3PublicInputs,
}

pub struct P3PublicInputs {
    pub ciphertext_hash: [u8; 32],
    pub plaintext_hash: [u8; 32],
    pub aggregate_pk_hash: [u8; 32],
    pub dkg_root: [u8; 32],
    pub epoch: u64,
    pub participant_set_hash: [u8; 32],
    pub d_commitment: [u8; 32],
}
```

Semantic contract:

- `fold` MUST reject mismatched `session_id`, mismatched `params`, non-fresh/randomness policy violations detected by the backend, malformed inner proofs, or any accumulator state that fails backend consistency checks.
- `fold` consumes exactly one frozen P1 proof/statement pair per step and returns a new accumulator with `fold_depth = acc.fold_depth + 1` on success.
- `verify_acc` checks accumulator well-formedness against `expected_params`, session binding, ordered-history binding, and backend commitment validity, but it does not expose backend-specific witness objects through this trait.
- `finalize` produces a terminal proof object suitable for P3 verification. Its `proof_bytes` are backend-defined, but the public-input boundary is frozen by `P3PublicInputs`.
- `FoldError` is intentionally abstract at this layer; implementations may define richer internal error categories without changing the frozen trait surface.

## Public-Input Layout (P3 Interface)

`P3PublicInputs` is serialized in the fixed order below. All hash fields are exactly 32 bytes. `epoch` is an unsigned 64-bit integer encoded big-endian. Total serialized size: 200 bytes.

| Field | Byte offset | Byte length | Derivation |
| --- | ---: | ---: | --- |
| `ciphertext_hash` | 0 | 32 | `SHA-256(concatenation of all nizk_statement.ciphertext_bytes for participating parties)` |
| `plaintext_hash` | 32 | 32 | `SHA-256` of aggregated plaintext; value is filled by P3 after decryption aggregation is fixed |
| `aggregate_pk_hash` | 64 | 32 | `SHA-256(aggregated BFV public key from DKG session)` |
| `dkg_root` | 96 | 32 | inherited from the P4 PVSS session root |
| `epoch` | 128 | 8 | fold session epoch number |
| `participant_set_hash` | 136 | 32 | `SHA-256` of the ordered participant id list |
| `d_commitment` | 168 | 32 | terminal `acc.statement_hash_chain` |

Additional binding notes:

- `ciphertext_hash` binds the exact ordered participant subset consumed by the fold session; implementers MUST use the same ordering convention as the participant list hashed into `participant_set_hash`.
- `plaintext_hash` is intentionally frozen at the interface even though P3 fills it, so P2 finalization already targets the exact downstream verifier boundary required by P2-T5.
- `aggregate_pk_hash` and `dkg_root` bind the final proof back to the originating DKG/PVSS session inherited from P4.
- `d_commitment` is the terminal ordered-statement digest exported from the accumulator and is the only fold-history commitment that P3 must treat as part of its fixed public-input surface.

## Adapter Strategy

All implementations MUST be hidden behind the `FoldingScheme` trait. The active backend is selected by Cargo feature:

- `surrogate-folding` (default): stub that always returns `Ok`
- `latticefold-plus`: real LatticeFold+ adapter (future)
- `micronova`: MicroNova adapter (fallback)
- `zkvm-folding`: Rust-in-zkVM adapter (delivery fallback)

Requirements:

- NO LatticeFold+-specific gadgets or field types in the public API.
- Backend-specific accumulator encodings, transcript projections, commitment schemes, or proof wrappers stay inside the selected adapter.
- The same `FoldStatement`, `FoldWitness`, `FoldAccumulator`, `FinalProof`, and `P3PublicInputs` surface must remain stable across all backend choices.
- Backend switching may change `acc_commitment` and `proof_bytes` internals, but MUST NOT change public field names, ordering, or semantics.

## Surrogate-Shape Contamination Policy

The design gate's `interface-spec` subcheck treats any direct mention of current surrogate verifier/circuit identifiers as a failure signal for surrogate leakage. The denylist includes the present contract verifier name (`Honk​Verifier`), wrapped-proof family name (`Ultra​Honk`), circuit-language marker (`No​ir`), surrogate package marker (`aggregator_​final`), and surrogate entry-file marker (`main.‌nr`). The public interface must stay semantic and backend-agnostic rather than inheriting shapes from temporary recursive surrogates.
