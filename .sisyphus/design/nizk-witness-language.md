# R3.0a NIZK Witness-Language Schema

Status: **draft — awaiting RED+GREEN implementation**.

Scope: define the canonical witness-language schema that bridges R3 NIZKs to the
R4 aggregator and R5 Nova step circuit, fixing the R3↔R4/R5 handoff gap.

Non-scope: Greco/MPCitH implementation, CRS binding, actual NIZK proof
generation/verification.

---

## 1. Schema Overview

The witness-language schema is the canonical contract between three phases:

| Phase | Role | Consumes |
|-------|------|----------|
| R3 (NIZK) | Produces proofs over witness-language statements | Schema types for statement construction |
| R4 (Aggregator) | Folds per-party NIZK instances | Schema types for deserializing witnesses |
| R5 (Compressor) | Wraps folded instance into Nova step circuit | Schema types for circuit public inputs |

All three phases share a single source of truth in `crates/pvthfhe-types/src/witness_language.rs`
— no ad-hoc byte layouts, no diverging serialization formats.

---

## 2. Field Representation

### 2.1 BFV Ring Parameters

The BFV scheme operates over `R_q = Z_q[X]/(X^N+1)`:

| Parameter | Symbol | Value |
|-----------|--------|-------|
| Ring degree | N | 8192 |
| Ciphertext modulus | q | ≈ 2^174 (3 RNS limbs × ~54 bits) |
| Secret bound | B_s | 1 (ternary: coefficients ∈ {-1, 0, 1}) |
| Randomness bound | B_r | 1024 (σ ≈ 3.19 × √(4/π) bootstrap bound) |
| Error bound | B_e | 16 (σ ≈ 3.19 discrete Gaussian) |

### 2.2 Witness Components as Coefficient Vectors

Every RLWE witness component (secret, randomness, noise) is represented as a
canonical coefficient vector of length N, with each coefficient stored as i64
in centred representation `(-q/2, q/2]`.

```
serialized_coeff_vector ::= [count: u32 BE] [coeff_0: i64 LE] ... [coeff_{N-1}: i64 LE]
```

### 2.3 Commitment Ring

R3 NIZK commitments operate over the smaller commitment ring
`R_{q_commit} = Z_{q_commit}[X]/(X^256+1)`:

| Parameter | Symbol | Value |
|-----------|--------|-------|
| Ring degree | φ | 256 |
| Commitment modulus | q_commit | 562 949 953 438 721 (≈2^49, prime) |
| Ajtai rank | a | 13 |
| Ajtai columns | m | 32 (= N/φ = 8192/256) |
| Witness bound | B_witness | 1024 |

---

## 3. Commitment Scheme

### 3.1 Ajtai Commitment (Current: Cyclo-conditional; Target: Greco)

```
Ajtai scheme:
  - Public matrix A ∈ R_{q_commit}^{a × m} derived from CRS-bound seed
  - Commitment: C = A · s ∈ R_{q_commit}^a  where s ∈ R_{q_commit}^m
  - Witness vector s is formed by chunking the RLWE witness of length N
    into m = N/φ chunks of φ = 256 coefficients each
  - Serialized commitment: a · φ · 8 = 13 × 256 × 8 = 26 624 bytes (i64 LE per coeff)
```

The commitment scheme is parameterized at the schema level so that R4
aggregation (which folds Ajtai commitments) and R5 compression (which
verifies folded commitments) can both reference the same parameters.

### 3.2 Hash Binding (D2 Pattern)

```
hash_binding = SHA256(session_id || participant_id_le || dkg_root || canonical_secret)
```

The hash binding links the NIZK statement to the DKG ceremony root,
preventing cross-session replay. The `dkg_root` is a Merkle root of
`(party_id, pk_i_hash)` pairs committed during DKG setup.

---

## 4. Statement-Bytes Serialization

### 4.1 Canonical Format (v1)

```
statement_bytes ::=
    version           : u16 BE  (= 0x0001)
    relation_id       : u32 BE  (0 = ShareWellFormedness, 1 = PartialDecryption)
    session_id_len    : u32 BE
    session_id        : [u8; session_id_len]
    participant_id    : u16 BE
    q_log2            : u64 BE
    ring_degree       : u64 BE
    error_bound       : u64 BE
    pk_len            : u32 BE
    pk_bytes          : [u8; pk_len]
    ct_len            : u32 BE
    ct_bytes          : [u8; ct_len]
    commitment_len    : u32 BE
    commitment_bytes  : [u8; commitment_len]
    dkg_root_len      : u32 BE
    dkg_root          : [u8; dkg_root_len]
```

All length prefixes are `u32 BE`. All integer fields are fixed-width. The
serialization is deterministic — no field ordering ambiguity, no optional
fields, no padding.

### 4.2 Version Negotiation

The version field `u16 BE` is checked first. If the verifier does not support
the version, it MUST reject with a schema-version error. Schema version 1 is
locked for Phase R3.0a through R5.

---

## 5. Secret vs Committed-and-Revealed-Later

### 5.1 Classification

| Witness Component | Classification | Zeroized? | Appears on Wire? |
|-------------------|---------------|-----------|------------------|
| `secret_share` (s_i) | SECRET | Yes (ZeroizeOnDrop) | Never |
| `encryption_randomness` (r_ij) | SECRET | Yes | Never |
| `decryption_noise` (e_i) | SECRET | Yes | Never |
| `secret_key` (sk_i) | SECRET | Yes | Never |
| `ajtai_commitment` (C = A·s) | COMMITTED | No | Yes (in proof body) |
| `hash_binding` | COMMITTED | No | Yes (in proof body) |
| `session_id`, `pk`, `ct`, `dkg_root` | PUBLIC | No | Yes (in statement) |

### 5.2 Rust Type Mapping

```rust
// Secret types (ZeroizeOnDrop, no serde)
pub struct WitnessSecret {
    pub secret_share:      ShareSecret,           // s_i coefficient vector
    pub randomness:        EncRandomness,          // r_ij coefficient vector
    pub noise:             NoisePoly,              // e_i coefficient vector
    pub secret_key:        Sk<Vec<u8>>,            // sk_i bytes
}

// Committed types (serde-friendly, appears on wire)
pub struct WitnessCommitment {
    pub commitment_bytes:  ProtocolBytes,          // 26 624-byte Ajtai commitment
    pub hash_binding:      ProtocolBytes,          // 32-byte SHA-256 binding
}

// Public statement (serde-friendly)
pub struct WitnessStatement {
    pub version:           WitnessSchemaVersion,
    pub relation:          R3Relation,
    pub session_id:        ProtocolBytes,
    pub participant_id:    u16,
    pub params:            BfvParameters,
    pub public_key:        ProtocolBytes,
    pub ciphertext:        ProtocolBytes,
    pub commitment:        ProtocolBytes,
    pub dkg_root:          ProtocolBytes,
}
```

Boundary rule: `WitnessSecret` MUST NEVER be serialized to wire format. Crossing
the crate boundary requires explicit `to_wire_bytes()`/`from_wire_bytes()` on
the newtypes for prototype wiring only. The R3.1 GREEN task removes the last
`to_wire_bytes()` call from the proof path.

---

## 6. Exact R3 NIZK Relation

### 6.1 Relation R3.1 — Share Well-Formedness

```
NP-statement:  x = (pk_j, (u_ij, v_ij), C_i, session_id, params)
NP-witness:    w = (s_i, {r_ij})

Relation R_shareWF(x, w) holds iff ALL of:
  (a) (u_ij, v_ij) = BFV.Encrypt(pk_j, m=s_i; r=r_ij) mod q
  (b) ‖s_i‖_∞ ≤ B_s
  (c) ∀j: ‖r_ij‖_∞ ≤ B_r
  (d) C_i = SHA256(session_id ‖ i_le ‖ canonical_s_i)

where:
  - BFV.Encrypt is canonical BFV encryption per fhe.rs
  - canonical_s_i is the deterministic LE coefficient serialization of s_i
  - i_le is the dealer index in little-endian encoding
```

### 6.2 Relation R3.2 — Partial Decryption

```
NP-statement:  x = (c, d_i, party_id, pk_i_hash, dkg_root, params)
NP-witness:    w = (sk_i)

Relation R_partialDecrypt(x, w) holds iff ALL of:
  (a) d_i = c · sk_i + e_i mod q  (RLWE decryption relation)
  (b) ‖e_i‖_∞ ≤ B_e
  (c) membership_proof(party_id, pk_i_hash, dkg_root) == Valid

where:
  - c is the input BFV ciphertext
  - d_i is the output partial-decryption share
  - e_i is the decryption noise (freshly sampled per decryption)
  - dkg_root is the Merkle root from DKG ceremony
```

### 6.3 Fold-Binding Invariant

The R4 aggregator folds instances where each instance's Ajtai commitment opens
to the witness. The R5 step circuit verifies the folded commitment. For the
fold-binding to be non-tautological:

- The NIZK statement's commitment field MUST be the same Ajtai commitment C
  that R4 expects to fold.
- The witness field representation (coefficient vectors) MUST use the same
  endianness and chunking (φ=256 groupings) as R4's fold step.
- The hash binding links the statement to the DKG root so that R4 cannot
  substitute a different witness for the same commitment without breaking
  the hash chain.

---

## 7. Schema Version Lifecycle

| Version | Active Since | Notes |
|---------|-------------|-------|
| V1 | R3.0a | Initial schema. Ajtai commitment + SHA-256 binding. Cyclo-conditional adapter. |
| V2 | (future) | Greco migration: commitment scheme may change; witness format stays. |
| V3 | (future) | MPCitH fallback: circuit-based commitment; different proof format. |

Version V1 is backward-incompatible with any future version. A proof encoded
under V1 MUST be rejected by a V2+ verifier unless a migration path is
explicitly specified.

---

## 8. Integration Points

### 8.1 Phase R3.1 (Share-WF NIZK)

`crates/pvthfhe-pvss/src/nizk_share.rs` imports `WitnessStatement`,
`WitnessSecret`, `WitnessCommitment`, `R3Relation::ShareWellFormedness`
and replaces its current `ShareNizkStatement` with the schema types.

### 8.2 Phase R3.2 (Partial-Decrypt NIZK)

`crates/pvthfhe-pvss/src/nizk_decrypt.rs` imports `WitnessStatement`,
`WitnessSecret`, `R3Relation::PartialDecryption` and replaces its current
`DecryptNizkStatement` with schema types.

### 8.3 Phase R4.1 (Aggregator)

`crates/pvthfhe-aggregator/src/folding/` imports `WitnessStatement`,
`WitnessCommitment`, `BfvParameters` and uses the schema serialization to
deserialize per-party statements before folding.

### 8.4 Phase R5.2 (Nova Step Circuit)

`crates/pvthfhe-compressor/src/nova/` imports `WitnessStatement`,
`BfvParameters` and uses schema types for public input transformation.

---

## 9. References

1. R3.0 construction selection: `.sisyphus/design/nizk-construction.md`
2. BFV parameters: `.sisyphus/design/parameters.md`
3. Ajtai commitment: `crates/pvthfhe-nizk/src/ajtai.rs`
4. PVSS spec: `.sisyphus/design/spec-pvss.md`
5. Decrypt spec: `.sisyphus/design/spec-decrypt.md`
6. Assumptions ledger: `.sisyphus/design/assumptions-ledger.md`
7. pvthfhe-types newtypes: `crates/pvthfhe-types/src/lib.rs`
8. Remediation plan: `.sisyphus/plans/pvthfhe-remediation.md` lines 279–284
