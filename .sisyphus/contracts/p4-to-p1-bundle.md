# P4→P1 Downstream Contract Bundle

This bundle freezes the P4 implementation handoff that P1 must consume before any decrypt-share proof work begins.

## Assumptions

- **Threshold privacy basis.** The implemented P4 secrecy claim is classical Shamir privacy over the prime field `p = 2^61 - 1`, not RLWE ciphertext hiding. The proved guarantee is that any coalition of fewer than `t` parties learns no information about the dealer secret beyond its own shares and the public transcript.
- **Threshold regime.** The protocol and proofs assume honest majority with `t = floor(n/2) + 1`, so any corrupted coalition must satisfy `|C| <= t - 1`; equivalently, P1 must not rely on settings with `t >= n` or dishonest-majority semantics.
- **Commitment model.** Public verifiability and blame rely on SHA-256 binding in the random-oracle / collision-resistance sense for commitments of the form `SHA256(session_id || participant_id || secret_value)`.
- **Authenticated transcript assumption.** The blame guarantees in P4 assume authenticated attribution of `dealer_id`, `participant_id`, and transcript/session metadata. False blame is excluded unless transcript agreement, message authentication, or SHA-256 binding fails.
- **Synchronous-session model.** The implemented P4 proofs assume a synchronous execution model with static corruption. Timeout/omission blame and adaptive corruption with erasures are explicitly out of scope for the frozen interface.
- **Semantic validation split.** `verify_transcript` checks structural artifact well-formedness, while semantic validity of a dealing is the replay check implemented by `public_verify` over accepted shares plus the accepted `PublicVerificationArtifact`.

## Public Key Format

- P4 exports a stub `BFVPublicKey` from `crates/pvthfhe-keygen/src/lib.rs`:

  ```rust
  pub struct BFVPublicKey {
      pub bytes: Vec<u8>,
  }
  ```

- The concrete P4 implementation in `HermineAdapter::reconstruct_bfv_key` serializes the reconstructed Shamir constant term as exactly eight **big-endian** bytes via `secret.to_be_bytes().to_vec()`.
- This means the current downstream contract is **not** an RLWE/BFV polynomial-key encoding. It is a placeholder byte handle that represents the reconstructed field element underlying the simulated Hermine session.
- P1 must therefore treat `BFVPublicKey.bytes` as opaque provenance-bound output from P4. It may reference those bytes in statements or witnesses, but it must not reinterpret them as a final BFV public key layout until the RLWE-backed key format replaces the stub.
- Provenance is carried externally by the associated `KeygenSession.session_id`, threshold, participant set, and `PublicVerificationArtifact`; the byte vector alone is insufficient without the frozen transcript context.

## Share Format

- P1 inherits the concrete share object implemented in `crates/pvthfhe-keygen/src/lib.rs`:

  ```rust
  pub struct Share {
      pub session_id: String,
      pub threshold: Option<u16>,
      pub participant_id: Option<u16>,
      pub secret_value: Option<u64>,
      pub commitment: Option<Vec<u8>>,
  }
  ```

- Semantics of each field:
  - `session_id`: ASCII/UTF-8 session label derived by P4 as `p4-hermine-<16 lowercase hex chars>` from the first eight bytes of a SHA-256 digest over participant IDs and threshold.
  - `threshold`: reconstruction threshold bound into the share and expected to equal the artifact threshold.
  - `participant_id`: 1-based participant identifier; zero and duplicates are invalid.
  - `secret_value`: Shamir evaluation `f(participant_id)` over the field `F_(2^61-1)`.
  - `commitment`: raw 32-byte SHA-256 digest for `(session_id, participant_id, secret_value)`.
- Well-formedness conditions already enforced by P4 and inherited by P1:
  - all shares in a batch must share the same `session_id` and `threshold`;
  - `participant_id` must be present, non-zero, and unique within the verified set;
  - `secret_value` must be present;
  - `commitment` must equal the recomputed canonical digest for that share.
- Reconstruction uses ordinary Shamir/Lagrange interpolation over `p = 2^61 - 1`; the share payload is a plain field element, not an encrypted RLWE share.

## Parameter Schema

The frozen P4→P1 parameter schema is:

| Parameter | Type | Source | Constraint / Meaning |
|---|---|---|---|
| `p` | `u64` constant | `crates/pvthfhe-keygen/src/hermine.rs` | `p = 2^61 - 1` (the Shamir field modulus) |
| `threshold` / `t` | `u16` | `KeygenSession.threshold`, `Share.threshold`, `PublicVerificationArtifact.threshold` | Must satisfy `1 <= t <= n`; threat model/proofs target honest majority `t = floor(n/2) + 1` |
| `participant_count` / `n` | `usize` | `KeygenSession.participants.len()` | Bench-plan sizes are `128`, `512`, `1024`; implementation requires `n > 0` |
| `participant_id` | `u16` | `Participant.id`, `Share.participant_id` | 1-based, unique within a session |
| `dealer_id` | `u16` | `PublicVerificationArtifact.dealer_id` | Identifies the dealer whose transcript is being verified |
| `session_id` | `String` | `KeygenSession.session_id` | Canonical session label, reused by shares, transcript, blame proofs, and key output |
| `session_id_bytes` | `Vec<u8>` | `KeygenSession.session_id_bytes` | Raw SHA-256 digest bytes from session derivation; provenance data for downstream binding |
| `commitment_scheme` | string constant | implementation/proofs | SHA-256 over `(session_id || participant_id || secret_value)` |
| `commitment_width` | `usize` constant | `verify_transcript` | Exactly 32 bytes per commitment |

- P1 statements that consume P4 artifacts must bind at least `session_id`, `participant_id`, `threshold`, and the SHA-256 commitment semantics above.
- Because the current key format is a stub, any downstream circuit or proof that claims BFV compatibility must explicitly state that the bytes encode the reconstructed Shamir secret placeholder rather than a final RLWE public key.

## Transcript Schema

- The public transcript object P1 must reference is the current P4 `PublicVerificationArtifact`:

  ```rust
  pub struct PublicVerificationArtifact {
      pub session_id: String,
      pub threshold: Option<u16>,
      pub commitments: Vec<Vec<u8>>,
      pub dealer_id: Option<u16>,
  }
  ```

- Field meanings:
  - `session_id`: common session label shared with all accepted shares.
  - `threshold`: threshold value bound into the transcript; missing threshold is invalid.
  - `commitments`: vector of raw 32-byte SHA-256 digests, one per participant share.
  - `dealer_id`: identifier of the dealer that published the transcript.
- Structural validity (`verify_transcript`) requires:
  - non-empty `session_id`;
  - `dealer_id` present;
  - `threshold` present;
  - non-empty `commitments` vector;
  - each element of `commitments` has length exactly 32 bytes.
- Semantic validity (`public_verify`) further requires:
  - one accepted share per published commitment;
  - exact session match between shares and artifact;
  - exact threshold match between shares and artifact;
  - unique participant identities;
  - recomputed per-share commitments equal both the share-local commitment field and the sorted published commitment multiset.
- Blame metadata inherited by downstream consumers comes from `BlameProof { session_id, reason, accused_id, evidence }`; this is part of the frozen handoff state named in the P4 composition proof.

## Encoding Commitments

- Canonical commitment function from `crates/pvthfhe-keygen/src/hermine.rs`:
  1. initialize SHA-256;
  2. append `session_id.as_bytes()`;
  3. append `participant_id.to_le_bytes()`;
  4. append `secret_value.to_be_bytes()`;
  5. finalize to a 32-byte digest.
- In Rust, the commitment is stored as raw digest bytes (`Vec<u8>`). For markdown documentation, logs, and any text-facing P1 interfaces, this bundle freezes the human-readable representation as **lowercase hexadecimal of those 32 bytes**.
- Accordingly, the textual commitment rule inherited by P1 is:

  `commitment = SHA-256(session_id || id || secret_value)`, rendered as lowercase hex when serialized to text.

- Endianness matters:
  - `participant_id` is encoded little-endian before hashing;
  - `secret_value` is encoded big-endian before hashing.
- P1 must not substitute alternative delimiters, JSON encoding, decimal strings, or field-width truncation when referencing the P4 commitment relation; it must bind the exact byte-level rule above and may only change the representation layer by converting the final digest bytes to lowercase hex for textual publication.

## Unresolved Risks

- **RLWE share-format gap.** The current share payload is a Shamir field element over `2^61 - 1`, while the eventual P1/P4 target stack expects lattice/RLWE semantics. Any P1 well-formedness proof built on this bundle must acknowledge that the witness shape is still a simulation artifact.
- **BFV key stub is underspecified for production use.** `BFVPublicKey.bytes` currently carries only eight big-endian bytes of the reconstructed secret placeholder. The eventual downstream contract will need a real BFV/RLWE public key schema (dimension, modulus chain, polynomial components, provenance binding, and serialization rules).
- **Commitment scheme may need upgrading for lattice NIZKs.** SHA-256 is adequate for the present public replay checks, but a future lattice-friendly statement system may require a commitment/hash domain separation story better aligned with circuit constraints or transcript Fiat-Shamir usage.
- **Artifact semantics split.** `verify_transcript` alone only enforces structural well-formedness; full semantic consistency requires replay against shares via `public_verify`. P1 must avoid assuming the artifact object by itself proves share well-formedness.
- **Static-corruption scope only.** Adaptive corruption, erasures, timeout blame, and network-level omissions are still unresolved and should not be silently inherited by P1 claims.
- **Cross-phase wording risk.** Because this bundle is the gate that authorizes P1 to start, downstream documents must continue to label the inherited P4 objects as simulated/stub where appropriate rather than overstating them as final RLWE artifacts.
