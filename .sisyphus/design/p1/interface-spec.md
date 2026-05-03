# P1 Frozen Interface Spec — NIZK API + Statement Encoding

## Scope

This document freezes the design-facing interface that the rest of PVTHFHE uses to invoke the Phase P1 lattice NIZK for decrypt-share well-formedness. The frozen boundary is protocol-semantic and backend-agnostic: callers construct statements, witnesses, and proofs in Rust-facing types without importing circuit-specific objects, proof-system wire labels, or backend-internal transcript terms.

The primary frozen proving direction is **SLAP**, with **Greyhound** and **Rust-in-zkVM** preserved as fallback backends behind the same trait boundary. The statement language is defined against the intended lattice relation, not against the current legacy surrogate.

## Design Constraints

- Bind the inherited P4 handoff exactly where it is already frozen: `session_id`, `participant_id`, threshold discipline, and the SHA-256 commitment model for `Share`.
- Bind the concrete FHE parameter tuple required by the P1 threat model and theorem inventory: `(q, N, B_e)` at minimum, with optional implementation metadata carried outside the core soundness relation.
- Keep the trait surface compatible with the style of `FheBackend`: opaque proof types, backend-specific internals hidden, deterministic serialization boundaries explicit.
- Preserve recursion-friendliness for downstream P2 folding by constraining proof size, public-input ordering, and verifier object complexity.
- Explicitly isolate the legacy surrogate behind an adapter and Cargo feature gate so the frozen interface does not inherit surrogate semantics by accident.

## Statement

`NizkStatement` is the public instance accepted by `verify` and `batch_verify`. It binds the exact public data that identifies one decrypt-share claim:

- `ciphertext_c: CiphertextHandle`
  - Opaque deterministic byte string for the ciphertext being partially decrypted.
  - The interface treats `c` as protocol data, not as a backend-native circuit type.
- `claimed_decrypt_share_d_i: DecryptShareHandle`
  - Opaque deterministic byte string for the claimed partial decrypt share.
- `pvss_commitment_hash: [u8; 32]`
  - The inherited P4 commitment digest.
  - Semantics are frozen to the P4 bundle rule:
    `SHA256(session_id.as_bytes() || participant_id.to_le_bytes() || secret_share_u64.to_be_bytes())`.
- `fhe_params: FheParamsBinding`
  - Must include at least:
    - `q: u64 | u128 | BigUint-encoded bytes` (chosen concrete host representation is backend-specific, but serialization must be canonical)
    - `ring_degree_n: u32`
    - `error_bound_b_e: u64`
- `session_id: SessionId`
  - Canonical UTF-8 PVTHFHE session label inherited from P4.
- `participant_id: u16`
  - 1-based participant identity.

The semantic relation frozen by this statement is:

1. the witness secret share corresponds to the inherited P4 commitment hash;
2. the witness opens a valid decrypt-share relation for ciphertext `c` and claimed share `d_i` under the bound FHE parameter tuple;
3. the witness error term satisfies the stated bound `B_e`;
4. the proof is scoped to exactly one `(session_id, participant_id)` pair.

### Statement encoding rules

- `session_id` is encoded as raw UTF-8 bytes, length-prefixed as `u32` in serialization contexts that require concatenation.
- `participant_id` is encoded as unsigned 16-bit little-endian when embedded in transcript or hash preimages.
- `pvss_commitment_hash` is exactly 32 bytes and is serialized byte-for-byte; text forms use lowercase hex.
- `ciphertext_c` and `claimed_decrypt_share_d_i` are opaque byte arrays with deterministic canonical encodings supplied by the active FHE backend or adapter.
- `q` must have a single canonical encoding per backend selection. If represented as bytes, it is unsigned big-endian without redundant leading zero bytes.
- `ring_degree_n` and `error_bound_b_e` are canonical unsigned integers.

## Witness

`NizkWitness` is prover-only data. It binds the private opening information for one participant:

- `secret_share_s_i: u64`
  - Inherited from the current P4 bundle as the Shamir field element used in the SHA-256 commitment relation.
  - This is frozen as a provenance-binding input; it does **not** claim that the long-term P4 artifact is permanently Shamir-native.
- `error_e_i: LatticeErrorVector`
  - Backend-agnostic lattice error vector used by the decrypt-share relation.
  - Stored as a deterministic sequence of signed coefficients or backend-defined canonical bytes.
- `randomness_r_i: RandomnessHandle`
  - The prover randomness / auxiliary witness material required by the concrete NIZK backend.
  - This is witness material only; it is never appended to the final proof bytes as a nondeterministic suffix.

### Witness semantics

The prover asserts knowledge of witness data such that:

- `pvss_commitment_hash = SHA256(session_id || participant_id || secret_share_s_i)` under the exact byte ordering frozen by P4;
- `claimed_decrypt_share_d_i` is consistent with `ciphertext_c`, `secret_share_s_i`, `error_e_i`, and the bound FHE parameters;
- `error_e_i` respects the norm / coefficient bound represented by `B_e`;
- `randomness_r_i` is valid for the selected backend but remains opaque to callers.

## Public Inputs

The canonical verifier-visible public-input layout is fixed in this order:

1. `version_tag`
2. `session_id_len`
3. `session_id_bytes`
4. `participant_id`
5. `ciphertext_c_len`
6. `ciphertext_c_bytes`
7. `claimed_decrypt_share_d_i_len`
8. `claimed_decrypt_share_d_i_bytes`
9. `pvss_commitment_hash[32]`
10. `q_len`
11. `q_bytes`
12. `ring_degree_n`
13. `error_bound_b_e`

### Layout rationale

- `session_id` and `participant_id` come first because they define the cross-phase identity binding inherited from P4/P2.
- `ciphertext_c` and `claimed_decrypt_share_d_i` follow as the direct decrypt-share claim.
- `pvss_commitment_hash` appears before FHE parameters so the verifier first binds the proof to the legacy provenance object before checking backend-specific arithmetic semantics.
- Length prefixes are part of the layout whenever a field is variable-width; omitting them is forbidden.

### Textual publication rules

- `pvss_commitment_hash`, `ciphertext_c_bytes`, `claimed_decrypt_share_d_i_bytes`, and `q_bytes` are rendered as lowercase hexadecimal in markdown, JSON, and review artifacts.
- `session_id` is rendered as UTF-8 text and must round-trip exactly.
- No decimal-string reinterpretation, JSON object reshaping, or delimiter-insertion is allowed between canonical serialization and verifier input construction.

## Proof Format

`NizkProof` is an opaque proof object with deterministic serialization. The frozen contract is:

- `NizkProof` must serialize to deterministic bytes for the same proof object.
- The serialized bytes must not carry any random per-call suffix, timestamp, nonce trailer, UUID, or backend logging residue.
- `NizkProof` must support `as_bytes()` / `from_bytes()`-style round trips at the adapter boundary, even if the final concrete API names differ.
- Proof metadata may include a backend identifier and version tag, but those fields must be part of the deterministic serialization contract.

### Required metadata

- `backend_id`: one of `slap`, `greyhound`, `rust-zkvm`, or `surrogate-adapter`
- `proof_version`: frozen integer revision
- `proof_bytes`: deterministic proof payload
- `constraint_estimate`: estimated verifier/recursion constraint count for downstream P2 budgeting
- `proof_size_bytes`: exact serialized proof length

### Recursion-friendly requirement

P2 consumes the P1 verifier output, so every proof record must publish a constraint-count estimate. The estimate may be static or backend-computed, but it must be attached to the proof object or derivable from it without re-running the prover. This is a design-time requirement, not a theorem claim.

## Serialization Contract

The serialization contract for all P1 interface objects is:

- Deterministic serialization only.
- One canonical byte encoding per object version.
- Stable field ordering for textual encodings used in fixtures, evidence, and adapter handoff.
- Explicit version tagging at the top level of every serialized object.
- Lowercase hex for byte strings when represented as text.
- No backend may inject transport-only metadata into the canonical form.

### Canonical object schemas

#### `NizkStatement`

- `version: u16`
- `session_id: String`
- `participant_id: u16`
- `ciphertext_c: Vec<u8>`
- `claimed_decrypt_share_d_i: Vec<u8>`
- `pvss_commitment_hash: [u8; 32]`
- `fhe_params: { q, ring_degree_n, error_bound_b_e }`

#### `NizkWitness`

- `version: u16`
- `secret_share_s_i: u64`
- `error_e_i: canonical vector bytes`
- `randomness_r_i: canonical bytes`

#### `NizkProof`

- `version: u16`
- `backend_id: string`
- `proof_version: u16`
- `constraint_estimate: u64`
- `proof_size_bytes: u32`
- `proof_bytes: Vec<u8>`

## Adapter Strategy

The adapter layer is responsible for translating the frozen semantic interface into whichever proof backend is active.

### Backend routing

- Default target after **B.I.2**: real lattice-native implementation behind the `LatticeNizk` trait.
- Temporary compatibility target: legacy surrogate adapter behind the Cargo feature `surrogate-decrypt-share`.
- Fallback backends (`greyhound`, `rust-zkvm`) are permitted only if they preserve the same statement and proof-object semantics.

### Adapter responsibilities

1. Accept `NizkStatement`, `NizkWitness`, and RNG input from callers.
2. Validate statement shape before handing off to a backend.
3. Normalize all opaque byte handles into the backend's internal representation.
4. Convert backend proof output into canonical `NizkProof` bytes and metadata.
5. Preserve the same `verify` and `batch_verify` semantics independent of backend choice.

### Trait layering

- The rest of PVTHFHE calls only the frozen `LatticeNizk` boundary.
- Backend-specific proof systems live behind adapter implementations.
- The adapter may internally call a surrogate circuit, a native lattice argument, or a zkVM proof, but none of those internal object names are exported through the frozen trait.

## Adapter Strategy for the Legacy Surrogate

The legacy surrogate remains available only as a temporary compatibility implementation.

- Cargo feature: `surrogate-decrypt-share`
- Default state after **B.I.2**: disabled; real implementation becomes the default backend
- Adapter role: wrap legacy proof generation/verification and map it into `NizkProof` with `backend_id = "surrogate-adapter"`

The surrogate adapter must:

1. accept the frozen `NizkStatement` / `NizkWitness` objects;
2. derive any surrogate-only helper inputs privately inside the adapter;
3. reject statements that cannot be faithfully projected into the surrogate relation;
4. clearly mark the emitted proof as surrogate-backed in metadata;
5. preserve deterministic proof serialization at the adapter boundary even if the underlying surrogate tooling requires internal preprocessing.

## Surrogate Boundary

The current `circuits/decrypt_share/src/main.nr` artifact is an implementation detail and not part of the frozen interface contract.

### Frozen isolation rules

- The interface spec must not depend on circuit-local witness wires, gadget names, or backend verifier contracts.
- The surrogate circuit's unconstrained hashes, Merkle bindings, shortness gadgets, and proof plumbing do not define the public API.
- Any surrogate-only fields needed for compatibility must be derived inside the adapter and must not appear in `NizkStatement`, `NizkWitness`, or `NizkProof`.

### Why the boundary is strict

- The scorecard explicitly freezes candidate selection against the intended RLWE-plus-transcript relation rather than the surrogate shape.
- The threat model and theorem inventory require public binding to `(session_id, participant_id, q, N, B_e)` and the P4 commitment hash; inheriting surrogate-specific public inputs would weaken or distort that claim.
- P2 compatibility depends on a stable verifier object that survives backend replacement without API churn.

## P2 Compatibility

The frozen interface is designed so P2 can fold accepted P1 proofs without reinterpreting witness semantics.

- `verify` and `batch_verify` consume the exact statement objects that P2 may later aggregate.
- `constraint_estimate` and `proof_size_bytes` give P2 the budgeting hooks it needs for recursion planning.
- `batch_verify` must fail on length mismatch, version mismatch, or backend-metadata inconsistency before backend-specific proof checks run.
- The interface intentionally exposes no simulator-only or extractor-only objects; P2 depends on the accepted proof/statement pair, not on implementation internals.

## Security Binding Notes

- Baseline theorem model remains ROM with rewinding extraction, consistent with the threat model.
- Simulation-soundness is not required for the frozen baseline and is therefore not encoded as an API promise.
- `pvss_commitment_hash` remains SHA-256-based because the inherited P4 public-verifiability story depends on that exact digest relation.
- The interface binds the current P4 surrogate provenance (`secret_share_s_i: u64`) while still leaving room for a future RLWE-native upstream artifact behind the same semantic statement boundary.
