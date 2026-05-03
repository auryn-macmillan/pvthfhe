# PVTHFHE Enclave-Compatible API Specification

**Version**: 0.1.0  
**Architecture**: B — Lattice PVSS + LatticeFold+ + MicroNova  
**Status**: Draft (T22)

---

## Overview

This document specifies the four primary interfaces of the PVTHFHE system:

1. **Party** — per-party key generation and partial decryption
2. **Aggregator** — share collection, proof folding, and result assembly
3. **VerifierClient** — stateless off-chain proof verification
4. **OnChainVerifier** — Solidity ABI for on-chain verification

All wire messages use **CBOR encoding** with a **4-byte big-endian length prefix**. This matches the T18/T19 wire format and is compatible with the gnosisguild/enclave transport layer.

### Enclave Adapter Mapping

The gnosisguild/enclave project exposes two primary roles:
- `ciphernode`: maps to the **Party** trait (holds a secret share, participates in DKG and decryption)
- `aggregator`: maps to the **Aggregator** trait (collects shares, folds proofs, emits results)

Adapters implementing these traits MUST NOT require upstream changes to enclave. They wrap enclave's existing message-passing interfaces and translate between enclave's internal types and PVTHFHE wire types. The adapter shape is read-only with respect to enclave internals.

---

## Wire Types

### High-level intuition

Wire types are the concrete byte-level representations of all messages exchanged between parties, aggregators, and verifiers. They are designed to be compact (CBOR) and unambiguous (all variable-length fields are length-prefixed). Every trait method either consumes or produces one of these types.

> **Transport prerequisite (normative)**: All wire messages MUST be transmitted over an authenticated channel. The protocol does not specify the transport layer; authentication (e.g., TLS-mTLS, signed envelopes) is a deployment concern. The `version` field is a format discriminator only — it provides no authentication or identity binding.

### Low-level formal

```
WireMessage := [u8; 4] (big-endian length) || CBOR(payload)
```

All sizes below are for the canonical parameter set (N=8192, L=3, log₂Q≈174):

| Type | Description | Approx. size |
|------|-------------|-------------|
| `RlwePk` | RLWE public key polynomial pair (a, b) ∈ Rq² | ~356 KB |
| `RlweShare` | Partial decryption share dᵢ ∈ Rq | ~178 KB |
| `EncShare` | Encrypted PVSS share for one recipient | ~178 KB |
| `NizkWellFormed` | LatticeFold+ NIZK for PVSS well-formedness | ~32 KB |
| `NizkDecShare` | LatticeFold+ NIZK for partial decryption | ~32 KB |
| `ComplaintProof` | Decryption failure witness | ~32 KB |
| `UltraHonkProof` | MicroNova-compressed UltraHonk SNARK | ~2 KB |
| `PlaintextPoly` | Plaintext polynomial in Rt (t=2^17) | ~16 KB |
| `KeygenMsg1` | Round-1 DKG broadcast | ~(n·178 + 32) KB |
| `KeygenMsg2` | Round-2 ack or complaint | ~32 KB |
| `KeygenMsg3` | Round-3 aggregate pk | ~356 KB |
| `DecryptShare` | Per-party decryption share + NIZK | ~210 KB |
| `DecryptResult` | Aggregated plaintext + proof | ~18 KB |

**CBOR field tags** (informative):
- `dealer_id`, `party_id`: CBOR uint
- `version`: CBOR uint (currently 0)
- `encrypted_shares`: CBOR array of bytes
- `nizk_well_formed`, `nizk`: CBOR bytes
- `share`: CBOR bytes
- `plaintext`: CBOR bytes
- `proof`: CBOR bytes
- `participant_set`: CBOR array of uint

---

## Interface 1: Party

### High-level intuition

The Party interface represents a single participant in the threshold FHE system. A party holds a secret key share `skᵢ` (a short ternary polynomial in Rq) and participates in two protocols: distributed key generation (DKG) and threshold decryption. During DKG, the party acts as a dealer — it samples its own secret, encrypts shares for all other parties using lattice PVSS, and broadcasts a NIZK proving well-formedness. During decryption, the party computes a partial decryption share with smudging noise and proves correctness via a LatticeFold+ NIZK. The Party trait maps to the `ciphernode` role in gnosisguild/enclave.

**⚠ Open Problem P1**: The `prove_share` and `generate_key_share` methods invoke LatticeFold+ NIZKs. The soundness of these lattice NIZKs is currently an open problem (P1). Implementations MUST document this limitation and MUST NOT deploy to production until P1 is resolved.

### Low-level formal

```rust
/// Errors returned by Party operations.
/// See also: PvthfheError enum below.
pub trait Party {
    /// Generate a key share and broadcast Round-1 DKG message.
    ///
    /// # Inputs
    /// - `party_id`: u32 — this party's identifier
    /// - `peer_pks`: &[RlwePk] — public keys of all n parties (for PVSS encryption)
    /// - `rng`: &mut dyn RngCore — cryptographically secure RNG
    ///
    /// # Output
    /// - `Ok(KeygenMsg1)` — CBOR+length-prefixed Round-1 broadcast
    ///   containing encrypted shares and NizkWellFormed (⚠ P1: soundness open)
    /// - `Err(PvthfheError)` — on parameter mismatch or RNG failure
    ///
    /// # Wire format
    /// `[u8;4 BE len] || CBOR { dealer_id: u32, encrypted_shares: [EncShare; n],
    ///                          nizk_well_formed: NizkWellFormed, version: u8 }`
    fn generate_key_share(
        &mut self,
        party_id: u32,
        peer_pks: &[RlwePk],
        rng: &mut dyn rand_core::RngCore,
    ) -> Result<KeygenMsg1, PvthfheError>;

    /// Compute a partial decryption share with smudging noise.
    ///
    /// # Inputs
    /// - `party_id`: u32 — this party's identifier
    /// - `ciphertext`: &Ciphertext — RLWE ciphertext (c₀, c₁) ∈ Rq²
    /// - `epoch`: u64 — replay-protection epoch/nonce
    /// - `rng`: &mut dyn RngCore — for smudging noise eᵢ ← χ_smudge (σ = 2^40·σ_err)
    ///
    /// # Output
    /// - `Ok(DecryptShare)` — CBOR+length-prefixed share dᵢ = c₁·skᵢ + eᵢ
    ///   with NizkDecShare (⚠ P1: soundness open)
    /// - `Err(PvthfheError)` — on missing key share or noise budget violation
    ///
     /// # Wire format
     /// `[u8;4 BE len] || CBOR { party_id: u32, pk_i_hash: [u8;32],
     ///                          dkg_root: [u8;32], ciphertext_hash: [u8;32],
     ///                          epoch: u64, share: RlweShare,
     ///                          nizk: NizkDecShare, version: u8 }`
     /// NIZK public inputs: (party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch, dᵢ)
     /// NIZK statement: dᵢ = c₁·skᵢ + eᵢ ∧ Keccak256(pkᵢ) = pk_i_hash ∧ ‖skᵢ‖,‖eᵢ‖ ≤ β
    fn partial_decrypt(
        &mut self,
        party_id: u32,
        ciphertext: &Ciphertext,
        epoch: u64,
        rng: &mut dyn rand_core::RngCore,
    ) -> Result<DecryptShare, PvthfheError>;

    /// Prove correctness of a partial decryption share (standalone, for re-proving).
    ///
    /// # Inputs
    /// - `share`: &DecryptShare — the share to prove
    /// - `ciphertext`: &Ciphertext — the ciphertext being decrypted
    ///
    /// # Output
    /// - `Ok(NizkDecShare)` — LatticeFold+ NIZK (⚠ P1: soundness open)
    /// - `Err(PvthfheError)` — on witness unavailability
    ///
    /// # Note
    /// This method is separated from `partial_decrypt` to allow proof regeneration
    /// without re-computing the share (e.g., for retransmission after network loss).
    fn prove_share(
        &self,
        share: &DecryptShare,
        ciphertext: &Ciphertext,
    ) -> Result<NizkDecShare, PvthfheError>;
}
```

---

## Interface 2: Aggregator

### High-level intuition

The Aggregator collects partial decryption shares from ≥t parties, verifies each share's NIZK, folds all valid NIZKs into a single LatticeFold+ accumulator, compresses the accumulator into a MicroNova UltraHonk SNARK, and assembles the final plaintext. The Aggregator is explicitly modeled as potentially malicious: it cannot learn any party's secret key share, and any misbehavior (equivocation, invalid aggregation) is publicly attributable. The Aggregator trait maps to the `aggregator` role in gnosisguild/enclave.

The `aggregate_proofs` method is separated from `aggregate_shares` to allow proof compression to be offloaded to a dedicated prover service without re-running share aggregation.

### Low-level formal

```rust
pub trait Aggregator {
    /// Collect and verify ≥t partial decryption shares, compute aggregate D = Σ dᵢ.
    ///
    /// # Inputs
    /// - `shares`: &[DecryptShare] — per-party shares (may include invalid ones)
    /// - `ciphertext`: &Ciphertext — the ciphertext being decrypted
    /// - `aggregate_pk`: &RlwePk — the aggregate public key pk = Σ pkᵢ
    /// - `threshold`: u32 — minimum number of valid shares required (t = ⌊N/2⌋+1)
    /// - `epoch`: u64 — replay-protection epoch/nonce
    ///
    /// # Output
    /// - `Ok(AggregateSharesResult)` — contains:
    ///   - `aggregate_d: RlweShare` — D = Σᵢ∈S' dᵢ (sum of valid shares)
    ///   - `valid_set: Vec<u32>` — party IDs of included shares
    ///   - `blame_set: Vec<BlameEntry>` — parties excluded with evidence
    ///   - `nizks: Vec<NizkDecShare>` — verified NIZKs for folding
    /// - `Err(PvthfheError::InsufficientShares)` — if <t valid shares
    /// - `Err(PvthfheError::ReplayDetected)` — if epoch mismatch
    ///
    /// # Security note
    /// Aggregator MUST verify each NizkDecShare before including the share.
    /// Unverified shares MUST NOT contribute to aggregate_d.
    fn aggregate_shares(
        &mut self,
        shares: &[DecryptShare],
        ciphertext: &Ciphertext,
        aggregate_pk: &RlwePk,
        threshold: u32,
        epoch: u64,
    ) -> Result<AggregateSharesResult, PvthfheError>;

    /// Fold verified NIZKs and compress into UltraHonk SNARK, then finalize plaintext.
    ///
    /// # Inputs
    /// - `agg_result`: AggregateSharesResult — output of aggregate_shares
    /// - `ciphertext`: &Ciphertext — the ciphertext being decrypted
    ///
     /// # Output
     /// - `Ok(DecryptResult)` — CBOR+length-prefixed final result:
     ///   - `plaintext: PlaintextPoly` — m = round((t_plain/q)·(c₀+D) mod q)
     ///   - `proof: UltraHonkProof` — MicroNova-compressed SNARK (~2 KB)
     ///   - `participant_set: Vec<u32>` — party IDs included in proof
     ///   - `dkg_root: [u8;32]` — DKG transcript root (session binding)
     ///   - `ciphertext_hash: [u8;32]` — Keccak256(ct) (replay protection)
     ///   - `epoch: u64` — decryption epoch
     ///   - `version: u8`
     /// - `Err(PvthfheError::ProofGenerationFailed)` — on SNARK failure
     ///
     /// # Wire format
     /// `[u8;4 BE len] || CBOR { plaintext: PlaintextPoly, proof: UltraHonkProof,
     ///                          participant_set: [u32], dkg_root: [u8;32],
     ///                          ciphertext_hash: [u8;32], epoch: u64, version: u8 }`
    fn aggregate_proofs(
        &mut self,
        agg_result: AggregateSharesResult,
        ciphertext: &Ciphertext,
    ) -> Result<DecryptResult, PvthfheError>;
}
```

---

## Interface 3: VerifierClient

### High-level intuition

The VerifierClient is a stateless off-chain verifier. It takes a ciphertext, a claimed plaintext, a UltraHonk proof, and the aggregate public key, and returns a boolean verdict. It has no access to any secret key material. This interface is designed to be callable from a light client, a browser, or a smart contract bridge. The VerifierClient maps to the public verifier algorithm in T19.

### Low-level formal

```rust
pub trait VerifierClient {
    /// Verify a threshold decryption result off-chain.
    ///
    /// # Inputs
    /// - `ciphertext`: &Ciphertext — the original RLWE ciphertext (c₀, c₁) ∈ Rq²
    /// - `plaintext`: &PlaintextPoly — the claimed plaintext m
    /// - `result`: &DecryptResult — contains proof Π and participant_set
    /// - `aggregate_pk`: &RlwePk — aggregate public key pk = Σ pkᵢ
    /// - `public_params`: &PublicParams — system-wide public parameters
    ///
    /// # Output
    /// - `Ok(true)` — proof valid, threshold met, consistency check passed
    /// - `Ok(false)` — any check failed (proof invalid, threshold not met, inconsistency)
    /// - `Err(PvthfheError::MalformedProof)` — proof bytes are structurally invalid
    ///
    /// # Verification steps (per T19)
    /// 1. Deserialize and structurally validate `result.proof` (UltraHonk)
     /// 2. Verify UltraHonk proof Π against frozen public inputs:
     ///    (ciphertext_hash, plaintext_hash, aggregate_pk_hash, dkg_root, epoch,
     ///     participant_set_hash, D_commitment)
     ///    where D_commitment = Keccak256(D) and D = Σᵢ∈S dᵢ
     /// 3. Check |participant_set| ≥ threshold
     /// 4. Check consistency: m = round((t_plain/q) · (c₀ + D) mod q)
     ///
     /// # Security note
     /// This method MUST NOT access any secret key material.
     /// All verification is via the SNARK proof Π.
     fn verify_decryption(
         &self,
         ciphertext_hash: &[u8; 32],
         plaintext_hash: &[u8; 32],
         aggregate_pk_hash: &[u8; 32],
         dkg_root: &[u8; 32],
         epoch: u64,
         participant_set_hash: &[u8; 32],
         d_commitment: &[u8; 32],
         proof: &UltraHonkProof,
         public_params: &PublicParams,
     ) -> Result<bool, PvthfheError>;
}
```

---

## Interface 4: OnChainVerifier (Solidity ABI)

### High-level intuition

The OnChainVerifier is a Solidity smart contract that verifies threshold decryption results on-chain. It exposes a single stateless `verify` function that accepts the ciphertext, plaintext, UltraHonk proof, aggregate public key, and participant set, and returns a boolean. The contract is designed to be called by any relayer or user who wants to confirm that a threshold decryption was performed correctly. Revert reasons are standardized for easy off-chain parsing.

### Low-level formal

#### Function signatures

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPvthfheVerifier {
    /// @notice Verify a threshold decryption result on-chain.
    ///
    /// Full RLWE objects (ciphertext, plaintext, aggregate pk) are NOT passed on-chain.
    /// Instead, their Keccak256 hashes are passed. The UltraHonk proof proves consistency
    /// between the proof witness and these hash commitments. This keeps calldata to ~14 KB.
    ///
    /// @param ciphertextHash    Keccak256 of CBOR-encoded ciphertext (c0 ∥ c1)
    /// @param plaintextHash     Keccak256 of CBOR-encoded plaintext polynomial
    /// @param aggregatePkHash   Keccak256 of CBOR-encoded aggregate public key
    /// @param dgkRoot           DKG transcript Merkle root (from keygen)
    /// @param epoch             Decryption epoch (replay protection)
    /// @param participantSetHash Keccak256 of ABI-encoded participant set (uint32[])
    /// @param proof             UltraHonk proof bytes (MicroNova-compressed, ~14 KB)
     /// @return valid            true iff proof verifies and all hash commitments are consistent
     function verify(
         bytes32 ciphertextHash,
         bytes32 plaintextHash,
         bytes32 aggregatePkHash,
         bytes32 dkgRoot,
         uint64  epoch,
         bytes32 participantSetHash,
         bytes32 dCommitment,
         bytes calldata proof
     ) external view returns (bool valid);

    /// @notice Returns the minimum threshold t = floor(N/2)+1 for the current parameter set.
    function threshold() external view returns (uint32);

    /// @notice Returns the RLWE degree N for the current parameter set.
    function rlweDegree() external view returns (uint32);
}
```

#### Calldata layout

Full RLWE objects are NOT passed on-chain — only their Keccak256 hashes. The SNARK proves
consistency between the proof witness and these commitments.

| Parameter | ABI type | Description | Size |
|-----------|----------|-------------|------|
| `ciphertextHash` | `bytes32` | Keccak256 of CBOR-encoded ciphertext | 32 B |
| `plaintextHash` | `bytes32` | Keccak256 of CBOR-encoded plaintext | 32 B |
| `aggregatePkHash` | `bytes32` | Keccak256 of CBOR-encoded aggregate pk | 32 B |
| `dkgRoot` | `bytes32` | DKG transcript Merkle root | 32 B |
| `epoch` | `uint64` | Decryption epoch (replay protection) | 8 B |
| `participantSetHash` | `bytes32` | Keccak256 of ABI-encoded participant set | 32 B |
| `dCommitment` | `bytes32` | Keccak256(D), D = Σᵢ∈S dᵢ (aggregate decryption sum) | 32 B |
| `proof` | `bytes` | UltraHonk proof (MicroNova-compressed, ~14 KB) | ~14 KB |

**Total on-chain calldata**: ~14.2 KB → calldata gas ≈ 14,200 × 16 = **227,200 gas** (well within 5M budget).

Full RLWE objects (ciphertext, plaintext, aggregate pk) are available off-chain via the aggregator.
The SNARK proves consistency between the proof witness and the hash commitments above.

#### Revert reasons

| Revert string | Condition |
|---------------|-----------|
| `"PVTHFHE: malformed proof"` | `proof` bytes fail UltraHonk structural check |
| `"PVTHFHE: threshold not met"` | participant set below threshold |
| `"PVTHFHE: proof verification failed"` | UltraHonk verifier returns false |
| `"PVTHFHE: epoch replay"` | `epoch` already consumed for this `dkgRoot` |
| `"PVTHFHE: unknown dkg root"` | `dkgRoot` not registered |

#### Enclave adapter note

The `IPvthfheVerifier` contract is called by the enclave `aggregator` role after emitting a `DecryptResult`. The adapter translates `DecryptResult` wire bytes into the ABI-encoded calldata above. No upstream enclave changes are required; the adapter is a pure translation layer.

---

## Error Types

### High-level intuition

All four interfaces share a common error enum `PvthfheError`. This ensures that error handling is uniform across the system and that all failure modes from T18 and T19 are covered. Each variant carries enough context for blame attribution and recovery.

### Low-level formal

```rust
/// Unified error type for all PVTHFHE interfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PvthfheError {
    /// A party's NIZK proof failed verification.
    /// Blame: the party identified by `party_id`.
    /// ⚠ P1: LatticeFold+ soundness is an open problem.
    MalformedNizk { party_id: u32 },

    /// A party's share is structurally invalid (wrong length, bad CBOR, etc.).
    MalformedShare { party_id: u32 },

    /// The aggregated DecryptResult is structurally invalid.
    MalformedAggregation,

    /// A UltraHonk proof failed structural validation (before verification).
    MalformedProof,

    /// Fewer than `threshold` valid shares were received.
    InsufficientShares { received: u32, threshold: u32 },

    /// A replay attack was detected (epoch/nonce mismatch).
    ReplayDetected { epoch: u64 },

    /// The aggregator equivocated (two different results for the same ciphertext).
    AggregatorEquivocation,

    /// Noise budget was exceeded (smudging noise too large for correct decryption).
    NoiseBudgetViolation { budget_bits: u32, used_bits: u32 },

    /// SNARK proof generation failed (MicroNova/UltraHonk backend error).
    ProofGenerationFailed { reason: String },

    /// Parameter mismatch (e.g., wrong N, wrong number of peers).
    ParameterMismatch { expected: String, got: String },

    /// RNG failure.
    RngFailure,

    /// Serialization/deserialization error (CBOR).
    SerializationError { reason: String },

    /// Blame matrix entry: a specific party is blamed with evidence.
    Blame { party_id: u32, evidence: Vec<u8> },
}
```

---

## Enclave Adapter Shape

The following describes the required adapter shape for mapping PVTHFHE traits to gnosisguild/enclave interfaces. This is read-only with respect to enclave internals.

```
EnclavePartyAdapter
  implements: Party
  wraps: enclave::ciphernode::Ciphernode
  translation:
    - generate_key_share → ciphernode.on_keygen_round1(msg) after CBOR encode
    - partial_decrypt    → ciphernode.on_decrypt_request(ct) after CBOR encode
    - prove_share        → internal (no enclave equivalent; standalone NIZK)

EnclaveAggregatorAdapter
  implements: Aggregator
  wraps: enclave::aggregator::Aggregator
  translation:
    - aggregate_shares → aggregator.on_shares_received(shares) after CBOR decode
    - aggregate_proofs → aggregator.on_proof_request(agg) after CBOR decode
```

No upstream enclave changes are required. Adapters are pure translation layers.

---

## Parameter Summary

| Parameter | Value |
|-----------|-------|
| N (RLWE degree) | 8192 |
| L (RNS limbs) | 3 |
| log₂(Q) | ≈174 |
| t (plaintext modulus) | 2^17 = 131072 |
| σ_err | 3.19 |
| σ_smudge | 2^40 · σ_err |
| Threshold | ⌊N/2⌋+1 |
| Security | ≥128-bit classical and post-quantum |
| Wire encoding | CBOR + 4-byte BE length prefix |
| NIZK backend | LatticeFold+ (⚠ P1: soundness open) |
| SNARK backend | MicroNova → UltraHonk (BB) |
