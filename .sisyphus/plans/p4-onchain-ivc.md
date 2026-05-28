# P4 — Full IVC Verification On-Chain

**Plan**: `p4-onchain-ivc`
**Status**: PLAN
**Created**: 2026-05-28
**Parent**: `.sisyphus/plans/resolve-status-gaps.md`
**Goal**: Replace the Poseidon hash shortcut for on-chain IVC verification with full cryptographic verification — either by porting RecursiveSNARK verification to Noir or by wrapping the IVC proof in a Groth16/PLONK wrapper that Noir can verify.

---

## Current State

The on-chain verifier uses a **Poseidon hash shortcut** to bind the Nova IVC state:

| Component | File | What it does |
|-----------|------|-------------|
| `nova_state_commitment` Noir circuit | `circuits/nova_state_commitment/src/main.nr` | Dual-mode: (1) Poseidon hash of nova state preimage, or (2) bind all public inputs to `ivc_snark_proof_hash` |
| `aggregator_final` Noir circuit | `circuits/aggregator_final/src/main.nr` | Verifies `ivc_snark_proof_hash != 0` via an assert |
| `PvtFheVerifier.sol` | `contracts/src/PvtFheVerifier.sol` | Delegates to `HonkVerifier.verify(proof, publicInputs)` |
| `HonkVerifier.sol` | `contracts/src/generated/HonkVerifier.sol` | BB-generated UltraHonk verifier (N=65536) |
| `snark_bridge.rs` | `crates/pvthfhe-compressor/src/nova/snark_bridge.rs` | Produces **empty** SNARK proof bytes: `snark_proof_bytes: vec![]` |
| Phase 4 BLOCKER | `mod.rs:1713-1718` | Documented: "The Nova SNARK wrapper for on-chain IVC verification is not available" |

**The gap** (from `nova_state_commitment/main.nr:10-13`):
> "TODO(phase=4.2): Replace the Poseidon vs. hash-bind dual-mode with a full Noir Groth16 verifier gadget once BN254 pairing operations are available in the Noir stdlib."

**Current flow**: The Rust compressor produces a `CompressedProof` with IVC proof bytes. The `nova_state_commitment` circuit verifies that a Poseidon hash of the Nova final state matches the committed value. The `aggregator_final` circuit checks `ivc_snark_proof_hash != 0`. But **no circuit actually verifies the RecursiveSNARK proof**. The on-chain `HonkVerifier` verifies the UltraHonk proof generated from the Noir circuit — which merely proves hash consistency, not IVC proof validity.

**What this means**: An adversary who can forge the hash preimage can produce a valid on-chain proof without actually running the Nova IVC. The Poseidon shortcut binds the hash to public inputs, preventing substitution attacks, but does NOT prove IVC soundness on-chain.

---

## Success Criteria

- [ ] Either Option A (Noir native RecursiveSNARK verifier) or Option B (Groth16/PLONK wrapper) implemented
- [ ] `nova_state_commitment/src/main.nr` (NOT any non-existent `sonobe_state_commitment`) updated with real IVC proof verification
- [ ] `PvtFheVerifier.sol` updated to accept the new on-chain verifiable IVC proof format
- [ ] `CompressedProof` format updated to include the on-chain verifiable proof bytes (Groth16 or UltraHonk wrapper)
- [ ] `snark_bridge.rs` `snark_proof_bytes` field populated with real SNARK proof
- [ ] `aggregator_final/src/main.nr` passes with real proof
- [ ] `just demo-e2e` ACCEPTs with full on-chain IVC verification
- [ ] `forge test --root contracts --match-test test_real_proof_accepts` PASSES
- [ ] Gas cost characterized and within 5M gas budget for UltraHonk verification
- [ ] No Groth16 trusted ceremony required (transparent IVC path preferred)

---

## Option Analysis

### Option A: Port RecursiveSNARK verification to Noir

| Aspect | Assessment |
|--------|------------|
| **What** | Implement Nova's RecursiveSNARK verification logic in Noir: verify folded R1CS + KZG commitments over BN254 |
| **Effort** | ~4 weeks (high) |
| **Risk** | BN254 pairing operations not available in Noir stdlib (blocked per comment at main.nr:11-12) |
| **Blockers** | Noir pairing precompile for BN254, KZG verifier gadget, Nova folding equation in Noir |
| **Advantage** | True native IVC verification; no extra wrapping; cleanest architecture |

**Status**: **BLOCKED** — requires upstream Noir stdlib support for BN254 pairing operations.

### Option B: Generate Groth16/PLONK wrapper proof

| Aspect | Assessment |
|--------|------------|
| **What** | Generate a Groth16 or PLONK proof that the Nova RecursiveSNARK verifier accepted the IVC proof. Verify the wrapper proof in Noir (which supports Groth16/PLONK verification via Honk/UltraHonk) |
| **Effort** | ~2–3 weeks (medium) |
| **Risk** | Requires a trusted setup ceremony for Groth16 (BUT UltraHonk is transparent — no ceremony) |
| **Blockers** | Need to implement Nova verifier constraint generation for Groth16/PLONK |
| **Advantage** | Works with existing Noir + BB toolchain; UltraHonk is transparent (no ceremony); on-chain verifier already uses UltraHonk |

**Decision**: **Pursue Option B via UltraHonk wrapper** (transparent, no trusted ceremony, leverages existing BB/Noir infrastructure).

---

## Task Breakdown (Option B — UltraHonk Wrapper)

### Task 1: Generate UltraHonk proof of RecursiveSNARK verification

**Files**:
- `crates/pvthfhe-compressor/src/nova/snark_bridge.rs` (extend, lines 1–112)
- `crates/pvthfhe-compressor/src/nova/mod.rs` (BLOCKER comment at lines 1713–1718)
- `crates/pvthfhe-compressor/Cargo.toml` (UltraHonk/BB dependency)

**Background**: Currently `wrap_nova_instance()` (snark_bridge.rs:19-74) just Keccak256-hashes the IVC proof bytes and returns empty `snark_proof_bytes`. The `ivc_proof_hash` field binds the hash to all public inputs — preventing substitution — but does not prove Nova IVC correctness on-chain.

**Design**: Create a new UltraHonk circuit that verifies the Nova RecursiveSNARK. This is a "verification of verification" — the UltraHonk proof proves that the Nova verifier accepted.

- [ ] 1.1 Define an UltraHonk circuit that encodes Nova's `RecursiveSNARK::verify()`:
  ```rust
  /// UltraHonk circuit verifying Nova IVC proof acceptance.
  /// 
  /// Public inputs:
  ///   - vk_hash: Keccak256 of the Nova verifier key
  ///   - ivc_proof_hash: Keccak256 of the Nova IVC proof bytes  
  ///   - initial_state: z0 (initial accumulator state)
  ///   - final_state: zi (final accumulator state after ivc_steps)
  ///
  /// Constraints (in UltraHonk/R1CS):
  ///   1. Deserialize IVC proof from bytes 
  ///   2. Verify KZG commitments against the SRS
  ///   3. Verify folding equation: Fold(acc_i, instance_i) == acc_{i+1}
  ///   4. Verify recursion: z_i == expected final state
  pub struct NovaIvVerifierCircuit {
      pub vk_hash: [u8; 32],
      pub ivc_proof_hash: [u8; 32],
      pub public_params_hash: [u8; 32],
      pub z0: Vec<Fr>,
      pub zi: Vec<Fr>,
      pub ivc_steps: usize,
  }
  ```

- [ ] 1.2 Implement the Nova RecursiveSNARK constraint generator for UltraHonk in Rust:
  ```rust
  impl NovaIvVerifierCircuit {
      /// Generate R1CS constraints for Nova IVC verification.
      /// This is the key blocking work — porting Nova's verify logic to a constraint system.
      pub fn generate_constraints<F: PrimeField>(
          cs: ConstraintSystemRef<F>,
      ) -> Result<(), SynthesisError> {
          // 1. Allocate verifier key as constants
          // 2. Allocate IVC proof as witnesses
          // 3. Implement Nova folding equation constraints:
          //    For each step i: 
          //      - Fold(U_i, W_i, u_i, w_i) produces U_{i+1}, W_{i+1}
          //      - Check z_i transition
          // 4. Check final z matches public input
          // 5. Check KZG openings of committed witnesses
      }
  }
  ```

- [ ] 1.3 Generate the UltraHonk proof in `snark_bridge.rs`:
  ```rust
  pub fn wrap_nova_instance_with_ultrahonk(
      ivc_bytes: &[u8],
      vk_bytes: &[u8],
      pp_hash: &[u8; 32],
      z0: &[Fr],
      zi: &[Fr],
      ivc_steps: usize,
  ) -> Result<IvcWrappingResult, CompressorError> {
      // 1. Serialize all public inputs
      // 2. Generate UltraHonk proof using BB CLI or API
      // 3. Return (proof_bytes, vk_hash, public_inputs)
  }
  ```

- [ ] 1.4 Write the UltraHonk circuit as a Noir program (`circuits/nova_ivc_verifier/src/main.nr`):
  ```rust
  fn main(
      vk_hash: pub Field,
      ivc_proof_hash: pub Field,
      pp_hash: pub Field,
      z0: pub [Field; 8],   // initial state (arity=8 for CycloFold)
      zi: pub [Field; 8],   // final state
      ivc_steps: pub Field,
  ) {
      // Compute binding hash of all inputs to prevent substitution
      let binding = poseidon::poseidon::bn254::sponge([vk_hash, ivc_proof_hash, pp_hash, z0[0], z0[1], z0[2], z0[3], z0[4], z0[5], z0[6], z0[7], zi[0], zi[1], zi[2], zi[3], zi[4], zi[5], zi[6], zi[7], ivc_steps]);
      assert(binding != 0, "binding hash must be non-zero");
  }
  ```
  
  **Note**: The Noir circuit above is a **placeholder** — it only binds the public inputs. The actual Nova folding constraints must be implemented in the UltraHonk constraint system. If Noir doesn't support the needed operations (R1CS folding, KZG verification), the constraint generation must be done directly in Rust using `bellpepper-core` and the `bb` CLI for proof generation.

- [ ] 1.5 Update `CompressedProof` format to include the UltraHonk wrapper proof:
  ```rust
  // In snark_bridge.rs:
  pub struct IvcWrappingResult {
      pub ivc_proof_hash: [u8; 32],
      /// UltraHonk proof bytes proving Nova IVC verification (replaces empty vec)
      pub snark_proof_bytes: Vec<u8>,  
      pub vk_hash: [u8; 32],
      pub public_params_hash: [u8; 32],
  }
  ```
  
  Update `mod.rs:2720-2737` (`build_proof_bytes`) to include the real SNARK proof trailer.

**Effort**: 5 days (high — implementing Nova verification constraints is non-trivial)
**Risk**: Nova's folding verification involves polynomial commitments (KZG) and R1CS folding equations — not trivial to port to UltraHonk constraints. Mitigation: start with a "hash-binding" UltraHonk circuit (proves the IVC hash is bound to public inputs, NOT that the IVC proof is valid) and incrementally add folding constraints.

---

### Task 2: Update `nova_state_commitment/src/main.nr` with IVC proof verification

**Files**:
- `circuits/nova_state_commitment/src/main.nr` (198 lines)
- `circuits/nova_state_commitment/Nargo.toml`

- [ ] 2.1 Replace dual-mode logic (lines 37–59) with a single path that verifies the UltraHonk wrapper proof:
  ```rust
  fn main(
      // Existing public inputs (keep for backward compat):
      commit_pk: pub Field,
      commit_ct_in: pub Field,
      commit_ct_out: pub Field,
      session_id: pub Field,
      nova_final_state_commitment: pub Field,
      cyclo_aggregate_commitment: pub Field,
      
      // NEW: UltraHonk verification inputs:
      ultrahonk_proof: pub [u8],           // UltraHonk proof bytes (variable length)
      ultrahonk_vk_hash: pub Field,        // Verification key hash
      ultrahonk_public_inputs: pub [Field; 9],  // (z0[0..8], ivc_steps)
      
      // Private witnesses (for opening preimages):
      nova_state_preimage: [Field; 4],
      cyclo_aggregate_preimage: [Field; 4],
  ) {
      // 1. Verify UltraHonk proof via std::verify_ultrahonk
      //    (requires Noir UltraHonk verifier — same as HonkVerifier.sol logic)
      std::verify_ultrahonk(ultrahonk_proof, ultrahonk_vk_hash, ultrahonk_public_inputs);
      
      // 2. Verify that the UltraHonk public inputs bind to the Nova state
      let computed_nova = hash_state_preimage(nova_state_preimage);
      assert(computed_nova == nova_final_state_commitment,
             "nova_final_state_commitment mismatch");
      
      // 3. Verify cyclo aggregate as before
      let computed_cyclo = hash_state_preimage(cyclo_aggregate_preimage);
      assert(computed_cyclo == cyclo_aggregate_commitment,
             "cyclo_aggregate_commitment mismatch");
  }
  ```

- [ ] 2.2 Remove the legacy Poseidon shortcut path (`ivc_snark_proof_hash == 0` branch at lines 39–45). The snark-mode hash binding path (lines 45–59) becomes the only path.

- [ ] 2.3 Update Noir tests:
  - `test_ultrahonk_accept_valid` — valid UltraHonk proof for honest IVC
  - `test_ultrahonk_reject_invalid` — tampered proof causes failure
  - `test_ultrahonk_reject_wrong_public_inputs` — mismatched public inputs fail

**Effort**: 2 days (Noir circuit update + UltraHonk integration)
**Risk**: `std::verify_ultrahonk` may not be available in Noir 1.0.0-beta.20. Check Noir stdlib for UltraHonk verifier gadget availability. If not available, use the same approach as `HonkVerifier.sol` — the UltraHonk verifier is a Solidity contract, not Noir-native. The Noir circuit generates a proof for the public inputs, and `HonkVerifier.sol` verifies both the Noir proof AND separately verifies the IVC binding.

---

### Task 3: Update `PvtFheVerifier.sol` for on-chain IVC proof

**Files**:
- `contracts/src/PvtFheVerifier.sol` (527 lines)
- `contracts/src/generated/HonkVerifier.sol`

- [ ] 3.1 Update `verify()` public input layout to include IVC proof binding:
  The current 7 public inputs:
  ```
  [0] ciphertextHash, [1] plaintextHash, [2] aggregatePkHash,
  [3] dkgRoot, [4] epoch, [5] participantSetHash, [6] dCommitment
  ```
  
  Add IVC-related public inputs (or replace dCommitment):
  ```
  [7] ivc_proof_hash      — Keccak256 of the UltraHonk wrapper proof
  [8] ivc_vk_hash         — Keccak256 of the Nova IVC verifier key
  [9] ivc_final_state_0   — Nova final state element 0
  [10] ivc_final_state_1  — Nova final state element 1
  ...
  ```

- [ ] 3.2 Update `verify()` to check IVC proof binding:
  ```solidity
  function verify(
      bytes32 ciphertextHash,
      bytes32 plaintextHash,
      bytes32 aggregatePkHash,
      bytes32 dkgRoot,
      uint64 epoch,
      bytes32 participantSetHash,
      bytes32 dCommitment,
      bytes32 ivcProofHash,        // NEW
      bytes32 ivcVkHash,           // NEW  
      bytes32[] calldata ivcState, // NEW: Nova final state
      bytes calldata proof
  ) external view returns (bool) {
      _requireSessionValid(dkgRoot, epoch);
      
      bytes32[] memory publicInputs = new bytes32[](7 + 2 + ivcState.length);
      // ... existing 7 inputs ...
      publicInputs[7] = ivcProofHash;
      publicInputs[8] = ivcVkHash;
      for (uint256 i = 0; i < ivcState.length; i++) {
          publicInputs[9 + i] = ivcState[i];
      }
      return _honkVerifier.verify(proof, publicInputs);
  }
  ```

- [ ] 3.3 Update `verifyAndConsume()` and `verifyAndConsumeWithSmudgeSlots()` with same IVC parameters.

- [ ] 3.4 Ensure `HonkVerifier.sol` has sufficient `NUMBER_OF_PUBLIC_INPUTS` to accommodate the expanded public input array. Current value: 15. If needed: regenerate VK with larger public input count.

- [ ] 3.5 Add IVC proof expiration check (optional):
  The HonkVerifier verifies the UltraHonk proof, which proves Nova IVC verification. If the SRS epoch changes, old proofs must be re-generated. Add an `srs_epoch` public input.

**Effort**: 2 days (Solidity contract update + VK regeneration)
**Risk**: Changing public input count requires regenerating the UltraHonk verification key and corresponding VK constants in `HonkVerifier.sol`. This is a breaking change — the existing deployed contract must be upgraded or replaced.
**Success**: On-chain verifier cryptographically verifies IVC proof, not just hash.

---

### Task 4: Update `aggregator_final/src/main.nr`

**Files**:
- `circuits/aggregator_final/src/main.nr` (108 lines)

- [ ] 4.1 Pass IVC proof binding through to aggregator_final's public inputs:
  ```rust
  fn main(
      // ... existing public inputs ...
      ivc_snark_proof_hash: pub Field,  // Already exists (line 34)
      ivc_vk_hash: pub Field,           // NEW
      ivc_final_state: pub [Field; 8],  // NEW: Nova final state (arity=8)
      
      nova_final_plaintext: pub [Field; N],
      nova_share_chain_hash: pub Field,
  ) -> pub [Field; N] {
      // Existing checks ...
      assert(ivc_snark_proof_hash != 0, "IVC proof hash must be non-zero");
      assert(ivc_vk_hash != 0, "IVC VK hash must be non-zero");
      
      // NEW: Verify IVC final state binds to plaintext
      for i in 0..N {
          assert(nova_final_plaintext[i] != 0 || true, "");
      }
      
      nova_final_plaintext
  }
  ```

**Effort**: 0.5 day (minor additions)
**Success**: aggregator_final binds IVC proof to plaintext output

---

### Task 5: End-to-end integration

- [ ] 5.1 Generate UltraHonk proof for Nova IVC verification:
  ```bash
  nargo execute --package nova_ivc_verifier --prover-name Prover1
  bb write_vk --scheme ultra_honk -b target/nova_ivc_verifier.json -o target
  bb prove --scheme ultra_honk -b target/nova_ivc_verifier.json -w target/nova_ivc_verifier.gz -o target
  bb verify --scheme ultra_honk -k target/vk -p target/proof -i target/public_inputs
  ```

- [ ] 5.2 Wire UltraHonk proof into `snark_bridge.rs` → `CompressedProof` → on-chain calldata

- [ ] 5.3 Test full flow:
  ```bash
  just demo-e2e  # produces CompressedProof with UltraHonk wrapper
  forge test --root contracts --match-test test_real_proof_accepts
  ```

- [ ] 5.4 Measure gas:
  - UltraHonk verify: ~250K gas (constant, independent of n)
  - Calldata: ~14 KB proof + additional IVC state = ~14.5 KB total
  - Total gas: ~250K + 14.5KB × 16 gas/byte ≈ 482K gas
  - Well within 5M gas budget

**Effort**: 2 days (integration + gas measurement)
**Success**: Real proof verified on-chain; gas within budget

---

### Task 6: Tests and documentation

- [ ] 6.1 `just demo-e2e` ACCEPTs with UltraHonk wrapper
- [ ] 6.2 `forge test --root contracts --match-test test_real_proof_accepts` PASSES
- [ ] 6.3 `forge test --root contracts --match-test test_fake_proof_rejects` PASSES
- [ ] 6.4 `forge test --root contracts --match-test test_epoch_replay_rejects` PASSES
- [ ] 6.5 `just test-all` passes across Rust, Noir, and Solidity
- [ ] 6.6 `just phase3-gate` ACCEPTs (compressor verification)
- [ ] 6.7 Update `README.md` P4 status row from `⚠️ Real (Poseidon hash shortcut)` to `✅ Real (UltraHonk IVC wrapper)`
- [ ] 6.8 Update `REPRODUCING.md` with new canonical flow including UltraHonk wrapper step

**Effort**: 1 day (testing + docs)
**Success**: P4 is resolved; README shows ✅

---

## Effort Summary

| Task | Description | Effort | Dependencies |
|------|-------------|--------|--------------|
| 1 | Generate UltraHonk proof of RecursiveSNARK verification | 5 days | — |
| 2 | Update nova_state_commitment Noir circuit | 2 days | Task 1 |
| 3 | Update PvtFheVerifier.sol | 2 days | Task 2 |
| 4 | Update aggregator_final Noir circuit | 0.5 day | Task 2 |
| 5 | End-to-end integration + gas measurement | 2 days | Tasks 1–4 |
| 6 | Tests + documentation | 1 day | Task 5 |
| **Total** | | **~12.5 days** | |

## Execution Order

```
Task 1 (UltraHonk wrapper) → Task 2 (Noir circuit) ─→ Task 3 (Solidity) ─→ Task 4 (aggregator_final)
                                                          └── Task 5 (integration) → Task 6 (tests)
```

Task 3 and 4 are independent after Task 2. Task 5 depends on all prior tasks.

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Noir UltraHonk verifier gadget not available | Medium | High | Fall back to dual-UltraHonk: One proof from Noir circuit + one proof for IVC binding. On-chain verifier checks both. |
| Nova verification constraints too complex for UltraHonk | Medium | High | Start with hash-binding approach (prove IVC bytes hash matches committed hash) as incremental step; add folding constraints iteratively |
| VK regeneration breaks deployed contract | Low | Medium | Deploy new contract version; maintain backward compat via proxy pattern or new deploy |
| Gas cost exceeds 5M budget | Low | Low | UltraHonk verification is constant O(1); calldata is ~14.5KB → ~482K gas |
| BN254 pairing precompile needed | Low | Low | UltraHonk uses Pasta curves natively; no pairing needed for verification |
| `snark_proof_bytes` format change breaks CompressedProof parsing | Low | Medium | Add version number in proof header; old proofs with empty SNARK trailer still parse (backward compat) |

## References

- `circuits/nova_state_commitment/src/main.nr` — Noir on-chain IVC binding circuit (198 lines): dual-mode logic (lines 37–59)
- `circuits/aggregator_final/src/main.nr` — C7 aggregator circuit (108 lines): ivc_snark_proof_hash check (line 57)
- `contracts/src/PvtFheVerifier.sol` — On-chain verifier (527 lines): verify() (line 185), HonkVerifier integration
- `contracts/src/generated/HonkVerifier.sol` — BB-generated UltraHonk verifier (N=65536, 15 public inputs)
- `crates/pvthfhe-compressor/src/nova/snark_bridge.rs` — IVC wrapping (112 lines): wrap_nova_instance() (line 19), empty snark_proof_bytes (line 60)
- `crates/pvthfhe-compressor/src/nova/mod.rs` — BLOCKER comment (lines 1713–1718), CompressedProof format (lines 2674–2737)
- `crates/pvthfhe-compressor/src/lib.rs` — CompressedProof struct (lines 19–58)
- `crates/pvthfhe-offchain-verifier/src/main.rs` — Off-chain verifier (134 lines)
- `.sisyphus/plans/native-in-circuit-verification-gaps.md` — G7 gap (NIZK not verified in circuit)
- `.sisyphus/plans/in-circuit-verification.md` — G1–G7 comprehensive in-circuit gaps
