# SURROGATE Retirement Status

**Date**: 2026-05-03  
**Basis**: surrogate-reachability.md (T2 deliverable)

Retirement = replacement of stub with real implementation.
"Prove dead" = documented evidence that the surrogate is unreachable in production paths.

---

## Summary Table

| Surrogate | Reachability | Retirement Status | Outcome |
|-----------|-------------|-------------------|---------|
| `crates/pvthfhe-fhe/src/fhers.rs` (FhersBackend) | LIVE (all profiles) | DEFERRED — see §1 | Open task |
| `contracts/src/generated/HonkVerifier.sol` | LIVE (all profiles) | DEFERRED — see §2 | Open task |
| `crates/pvthfhe-aggregator/src/keygen/protocol.rs` | Compiled, zero symbols | PROVED DEAD — see §3 | ✅ Dead |
| `circuits/aggregator_final/src/main.nr` | DEAD (Rust); TEST-ONLY (Noir) | PROVED DEAD — see §4 | ✅ Dead |
| `circuits/decrypt_share/src/main.nr` | DEAD (Rust); TEST-ONLY (Noir) | PROVED DEAD — see §5 | ✅ Dead |

---

## §1: FhersBackend — DEFERRED

**File**: `crates/pvthfhe-fhe/src/fhers.rs`  
**Status**: LIVE. All four trait methods (`load_params`, `keygen_share`, `encrypt`,
`decrypt_share`) delegate to `MockBackendInner`. No real FHE operation is performed.

**Why deferred**: Replacing this surrogate requires integrating a real FHE backend
(Poulpy or `gnosisguild/fhe.rs`, per AGENTS.md "FHE backends" policy). The backend
choice is explicitly deferred to T4 (AGENTS.md). Integration requires:
- Selecting and vendoring the FHE library
- Implementing `FheBackend` trait against live Ring-LWE primitives
- Validating key correctness with end-to-end tests

**Blocking**: FHE backend selection (deferred per AGENTS.md T4).  
**Open task marker**: `SURROGATE-FhersBackend-OPEN`

---

## §2: HonkVerifier.sol — DEFERRED

**File**: `contracts/src/generated/HonkVerifier.sol`  
**Status**: LIVE. Imported and instantiated by `PvtFheVerifier.sol`. The Solidity
`verify()` method performs a keccak-equality check against a hard-coded constant —
not a real UltraHonk verification.

**Why deferred**: A real Honk verifier requires:
1. The P2 fold circuit (`circuits/p2_fold`) to exist and produce a valid proof artifact
2. `bb write_vk` + `bb contract` to export a Solidity verifier from the circuit VK
3. P3 integration test (`just verify-onchain`) to pass with real proofs

Currently the `real-folding` feature is dead in production (p2-reachability.md).
The entire P2 circuit pipeline must be built first.

**Blocking**: P2 circuit implementation (open research problem, noted in README).  
**Open task marker**: `SURROGATE-HonkVerifier-OPEN`

---

## §3: keygen/protocol.rs — PROVED DEAD

**File**: `crates/pvthfhe-aggregator/src/keygen/protocol.rs`  
**Evidence**: The file contains 4 lines of comments and zero Rust items. `pub mod
protocol` in `keygen/mod.rs` compiles the module but nothing is exported or imported
downstream. `grep -rn "protocol::"` in the aggregator crate returns zero matches.

**Retirement verdict**: Dead — no replacement needed. The module is a comment
placeholder; retirement means deleting it once a real protocol implementation exists.

---

## §4: circuits/aggregator_final — PROVED DEAD (Rust)

**File**: `circuits/aggregator_final/src/main.nr`  
**Evidence**: No Rust crate references this Noir package. `pvthfhe-circuits/src/lib.rs`
is a placeholder. Dead under all `cargo` profiles. TEST-ONLY under `nargo test`.

**Retirement verdict**: Dead in Rust production paths. The Noir circuit is a standalone
research artifact that does not participate in Rust-driven proof generation until P2 is
wired end-to-end.

---

## §5: circuits/decrypt_share — PROVED DEAD (Rust)

**File**: `circuits/decrypt_share/src/main.nr`  
**Evidence**: No Rust crate imports or invokes this Noir package. The `surrogate-
decrypt-share` Cargo feature is an independent flag gating Rust NIZK shim behaviour,
not the Noir circuit. Dead under all `cargo` profiles. TEST-ONLY under `nargo test`.

**Retirement verdict**: Dead in Rust production paths. Same caveat as §4.
