# P4 Frozen Interface Spec

## Scope

This document freezes the design-facing Rust surface and JSON wire formats for the Hermine-adapted P4 keygen boundary. It intentionally does **not** inherit the surrogate shape in `crates/pvthfhe-aggregator/src/keygen/protocol.rs`; an adapter layer will translate later.

The frozen objects are:

1. `KeygenSession`
2. `Share`
3. `PublicVerificationArtifact`
4. `BlameProof`
5. `BFVPublicKey` plus its derivation trait

All wire encodings use `serde` + `serde_json` with explicit snake/flat field names shown below.

## Design constraints

- Primary construction: Hermine-adapted PVSS, per `.sisyphus/research/p4/candidate-scorecard.md`.
- Threat model: static corruption, honest-majority threshold `t = floor(n/2) + 1`, synchronous network.
- Final interfaces are protocol-semantic objects, not transport packets from the surrogate coordinator.
- `BFVPublicKey` is the downstream adapter product that binds the reconstructed RLWE public key to the publicly verifiable transcript.

## Rust trait surface

```rust
pub trait KeygenSessionSpec: Sized + Serialize + DeserializeOwned {
    fn session_id(&self) -> &str;
    fn participants(&self) -> &[Participant];
    fn threshold(&self) -> u16;
    fn phase(&self) -> &KeygenPhase;
    fn to_wire_json(&self) -> SpecResult<String>;
    fn from_wire_json(wire_json: &str) -> SpecResult<Self>;
}

pub trait ShareSpec: Sized + Serialize + DeserializeOwned {
    fn session_id(&self) -> &str;
    fn dealer_id(&self) -> u16;
    fn recipient_id(&self) -> u16;
    fn commitment(&self) -> &Commitment;
    fn to_wire_json(&self) -> SpecResult<String>;
    fn from_wire_json(wire_json: &str) -> SpecResult<Self>;
}

pub trait PublicVerificationArtifactSpec: Sized + Serialize + DeserializeOwned {
    fn session_id(&self) -> &str;
    fn dealer_id(&self) -> u16;
    fn share_commitments(&self) -> &[Commitment];
    fn to_wire_json(&self) -> SpecResult<String>;
    fn from_wire_json(wire_json: &str) -> SpecResult<Self>;
}

pub trait BlameProofSpec: Sized + Serialize + DeserializeOwned {
    fn session_id(&self) -> &str;
    fn accuser_id(&self) -> u16;
    fn accused(&self) -> &BlameTarget;
    fn reason(&self) -> &BlameReason;
    fn to_wire_json(&self) -> SpecResult<String>;
    fn from_wire_json(wire_json: &str) -> SpecResult<Self>;
}

pub trait BfvPublicKeyDerivation {
    fn derive_bfv_public_key(
        &self,
        session: &KeygenSession,
        shares: &[Share],
    ) -> SpecResult<BFVPublicKey>;
}
```

## Type definitions

### 1. `KeygenSession`

Purpose: immutable session context for one Hermine-adapted public keygen instance.

Required fields:

- `wire_version: u16`
- `session_id: String`
- `epoch: u64`
- `threshold: u16`
- `participants: Vec<Participant>`
- `phase: KeygenPhase`
- `transcript_domain: String`

### 2. `Share`

Purpose: one dealer-to-recipient encrypted share plus its binding commitment.

Required fields:

- `wire_version: u16`
- `session_id: String`
- `dealer_id: u16`
- `recipient_id: u16`
- `share_index: u16`
- `encrypted_share: HexBlob`
- `commitment: Commitment`
- `proof_ref: String`

### 3. `PublicVerificationArtifact`

Purpose: full public transcript fragment needed for third-party verification of one dealer publication.

Required fields:

- `wire_version: u16`
- `session_id: String`
- `dealer_id: u16`
- `share_commitments: Vec<Commitment>`
- `transcript_root: HexBlob`
- `well_formedness_statement: String`
- `proof_bytes: HexBlob`
- `bfv_derivation_label: String`

### 4. `BlameProof`

Purpose: abort-with-blame evidence package naming the accused actor and carrying public evidence.

Required fields:

- `wire_version: u16`
- `session_id: String`
- `accuser_id: u16`
- `accused: BlameTarget`
- `reason: BlameReason`
- `evidence: Vec<EvidenceItem>`

### 5. `BFVPublicKey`

Purpose: BFV-format public key emitted by the adapter boundary after transcript-checked reconstruction.

Required fields:

- `wire_version: u16`
- `session_id: String`
- `params_id: String`
- `rlwe_dimension: u32`
- `modulus_chain: Vec<u64>`
- `public_component_a: HexBlob`
- `public_component_b: HexBlob`
- `provenance: BfvKeyProvenance`

## Wire format details

### Shared conventions

- `HexBlob` is serialized as a plain JSON string containing lowercase hexadecimal without separators.
- All `wire_version` values are fixed to `1` for this frozen revision.
- Field order is not cryptographically significant, but examples below reflect the canonical human-facing order used in KAT fixtures.
- `BlameTarget` is a serde tagged enum using `{"kind": ...}`.

### Canonical `KeygenSession` JSON

```json
{
  "wire_version": 1,
  "session_id": "p4-session-alpha",
  "epoch": 7,
  "threshold": 3,
  "participants": [
    { "participant_id": 1, "encryption_key_ref": "enc-pk-01" }
  ],
  "phase": "finalized",
  "transcript_domain": "pvthfhe.p4.hermine.v1"
}
```

### Canonical `Share` JSON

```json
{
  "wire_version": 1,
  "session_id": "p4-session-alpha",
  "dealer_id": 11,
  "recipient_id": 1,
  "share_index": 0,
  "encrypted_share": "a1b2c3d4",
  "commitment": {
    "scheme": "hermine_commit_v1",
    "digest": "0abc"
  },
  "proof_ref": "stmt-share-0"
}
```

### Canonical `PublicVerificationArtifact` JSON

```json
{
  "wire_version": 1,
  "session_id": "p4-session-alpha",
  "dealer_id": 11,
  "share_commitments": [
    { "scheme": "hermine_commit_v1", "digest": "0abc" }
  ],
  "transcript_root": "feedcafe",
  "well_formedness_statement": "hermine.dealer.statement.v1",
  "proof_bytes": "bead01",
  "bfv_derivation_label": "bfv-params/toy-v1"
}
```

### Canonical `BlameProof` JSON

```json
{
  "wire_version": 1,
  "session_id": "p4-session-alpha",
  "accuser_id": 2,
  "accused": { "kind": "dealer", "dealer_id": 11 },
  "reason": "commitment_mismatch",
  "evidence": [
    {
      "label": "transcript-slice",
      "digest": "9999aaaa",
      "payload": "01020304"
    }
  ]
}
```

### Canonical `BFVPublicKey` JSON

```json
{
  "wire_version": 1,
  "session_id": "p4-session-alpha",
  "params_id": "bfv-params/toy-v1",
  "rlwe_dimension": 4096,
  "modulus_chain": [4294962689, 4294951937],
  "public_component_a": "feedcafe01",
  "public_component_b": "bead0102",
  "provenance": {
    "reconstructed_from_share_ids": [1, 2, 3],
    "transcript_root": "feedcafe"
  }
}
```

## BFV derivation boundary

`BfvPublicKeyDerivation` is implemented on `PublicVerificationArtifact`, not on the surrogate coordinator. The derivation boundary is:

1. confirm `session.session_id == artifact.session_id`
2. require non-empty `shares`
3. require every `Share.session_id` to match the session
4. derive a BFV-form object bound to the transcript root and contributing share ids

This keeps the P4 interface semantic: session + transcript + shares are the only frozen inputs, and downstream BFV backends consume `BFVPublicKey` without inheriting coordinator internals.

## Adapter note

`crates/pvthfhe-aggregator/src/keygen/protocol.rs` remains an adapter concern only. No field names or trait methods in this spec are borrowed from the current surrogate stub.
