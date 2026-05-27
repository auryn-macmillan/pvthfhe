# PVTHFHE Comprehensive Security Review — May 18, 2026

**Scope**: Paper, implementation, documentation, and all plan files.
**Focus**: Malicious committee members and aggregators — halt, corrupt, or exfiltrate.
**Method**: 7 parallel background audit agents (explore + librarian) across all crates, circuits, contracts, CLI, and plans.

---

## Cross-Referenced Findings (Deduplicated)

Total raw findings across 7 audits: ~120. After deduplication and cross-referencing against already-resolved work: **32 actionable findings remain**.

### Already Addressed / Not Actionable

| Finding | Resolution |
|---------|-----------|
| sigma_verify_step returns Ok(1) when no data | Track A compatibility — intentional. Track B enforces full verification. |
| cyclo_witness_or_default returns zeros | Same — Track A design. |
| Ternary scalar challenge (1/3 soundness) | Scalar-challenge sigma redesign with (1/3)^10 soundness. Standard sigma protocol. |
| Ajtai commitment not verified in verify() | By design — serves as session binding, not verifiable opening (verifier lacks witness). |
| G-LAGRANGE/G-PLAINTEXT fixes | Lagrange coefficients + plaintext computation moved into Noir circuit. |
| G2 full in-circuit Poseidon | DONE — 639K constraints/step. |
| G7 scalar-challenge sigma redesign | DONE — proof version 0x0002. |
| G3/G4/G6/G13 Phase 1 bindings | DONE — bound into d_commitment. |
| Track A compatibility (ring_inc/sigma always FpVar::one()) | DONE. |

---

## Actionable Findings — By Category

### A. Hash Chain & Protocol Binding (5 findings)

**A.1 [CRITICAL] — Three incompatible d_commitment definitions**
- Pipeline: Poseidon BN254 `bind_8_with_domain_native` (domain 6)
- e2e_real test: SHA-256 of compressed proof bytes
- witness_gen test: `rolling_digest_8_raw` (custom rolling hash)
- A verifier expecting one will reject the other.
- **Fix**: Canonicalize to Poseidon `bind_8_with_domain_native` domain 6 everywhere.

**A.2 [CRITICAL] — d_commitment only binds C7 decryption aggregation**
- Keygen transcript, NIZK keygen proofs, PVSS share encryption, fold accumulators, compressed proof digest, ciphertext, and plaintext are NOT in d_commitment.
- Malicious aggregator can change any of these undetected.
- **Fix**: Extend d_commitment to include: keygen_transcript_hash, all_nizk_proofs_hash, fold_accumulator_hash, compressed_proof_digest, ciphertext_hash. Reorder to match pipeline step sequence.

**A.3 [CRITICAL] — No end-to-end d_commitment verification**
- d_commitment is computed and written to Prover.toml but never cross-checked against pipeline state in `run_full_pipeline()`.
- The Noir circuit verifies internal consistency only.
- **Fix**: Add post-pipeline assertion in `PipelineReport` comparing computed d_commitment to Noir-verified value.

**A.4 [HIGH] — d_commitment circular binding**
- Prover (aggregator) controls BOTH `participant_shares` (witness) AND `d_commitment` (public input).
- Circuit recomputes and asserts match — but both originate from the same untrusted source.
- **Fix**: d_commitment must be verifier-supplied (on-chain posted before proof generation) or bound to independently verifiable data (e.g., decrypt_share proofs commit to individual d_i hashes).

**A.5 [MEDIUM] — d_commitment absent from Fiat-Shamir challenge derivation**
- C7 challenge `r = Poseidon(commitment, dkg_root_hash)` — d_commitment not absorbed.
- NIZK sigma challenge binds `(t_rns, c_rns, d_rns, pvss_commitment)` — also no d_commitment.
- Prover can tamper d_commitment without affecting challenge.
- **Fix**: Absorb d_commitment into all Fiat-Shamir challenge derivations.

### B. Noir Circuit Soundness (7 findings)

**B.1 [CRITICAL] — `participant_shares` witness completely unconstrained**
- `aggregator_final` line 82: shares used in Lagrange interpolation and combined_share_hash.
- Only constraint: hash matches d_commitment (circular — see A.4).
- No verification that shares satisfy R3 partial-decrypt relation, belong to correct parties, or are valid threshold shares.
- Aggregator with ZERO real shares can fabricate everything and produce valid proof.
- **Fix**: Either (a) verify each share against individual decrypt_share proofs in-circuit, or (b) require verifier-published combined_share_hash that aggregator cannot recompute.

**B.2 [HIGH] — `committee_party_ids` not bound to `participant_set_hash` or `dkg_root`**
- `participant_set_hash` only checked `!= 0` (line 85).
- No constraint linking committee_party_ids to participant_set_hash.
- Aggregator can substitute arbitrary party IDs producing different Lagrange coefficients.
- **Fix**: Add `vector_hash(committee_party_ids[0..n], DOMAIN) == participant_set_hash`.

**B.3 [MEDIUM] — `threshold` never enforced in interpolation**
- All `n` shares used regardless of threshold (lines 126-135).
- Verifier expecting t-of-n gets n-of-n silently.
- **Fix**: Enforce that exactly `threshold` shares are used, or that n-t shares are zero.

**B.4 [HIGH] — `share_wf` `pk_hash` completely unconstrained**
- `share_wf/src/main.nr` line 13: `let _ = pk_hash;` — public input discarded.
- Circuit verifies share commitment but NOT that share is encrypted under claimed public key.
- File still exists on disk (removed from workspace but not deleted).
- **Fix**: Delete the file entirely. If circuit is needed, add `pk_hash` constraint.

**B.5 [MEDIUM] — `decrypt_share` lacks `party_id != 0` assertion**
- `party_id` used in hash bindings but never checked non-zero.
- Share could be attributed to non-existent party_id 0.
- **Fix**: Add `assert(party_id != 0)`.

**B.6 [LOW] — `e_i` bound check potential edge case**
- `decrypt_share` lines 83-90: uses `err as u32` cast for signed bound check.
- Theoretical edge case if modulus lower 32 bits produce false negative.
- **Fix**: Use explicit signed comparison or decompose into bit range check.

**B.7 [LOW] — `nova_state_commitment` preimages are 4-field elements (prototype)**
- Insufficient for real Nova state. Documented limitation.

### C. FHE Backend & NIZK (5 findings)

**C.1 [CRITICAL] — No duplicate party_id check in `aggregate_decrypt` (FhersBackend)**
- `fhers.rs` lines 1200-1206: validates range but not uniqueness.
- Mock backend HAS the check (`mock_impl.rs:170-177`) but FhersBackend does not.
- Duplicate shares corrupt Lagrange interpolation.
- **Fix**: Add `seen.contains(&share.party_id)` check.

**C.2 [HIGH] — No cryptographic binding of shares to sender identity**
- `DecryptShare` has `party_id: u32` with no signature, MAC, or proof of origin.
- Any party can produce a share with any party_id.
- **Fix**: Bind share to NIZK proof that includes party_id and session binding, or add signature.

**C.3 [HIGH] — Secret key material accessible through `party_state`**
- `fhers.rs` line 60: `Arc<Mutex<HashMap<u32, PartyState>>` — any code holding the lock reads all parties' secret keys.
- `party_secret_key_bytes()` (line 100) has no access control.
- **Fix**: Restrict access with capability or move to per-party isolate.

**C.4 [MEDIUM] — Lagrange coefficient overflow for n > 35**
- `compute_lagrange_coeffs_integer` uses i128 (lines 1691-1693).
- n=1024 produces ~10^2600 products, massively exceeding i128::MAX.
- **Fix**: Use BigInt or modular arithmetic in the field directly.

**C.5 [MEDIUM] — CRT reconstruction silently replaces overflow with `i128::MAX`**
- `crt_reconstruct_coeffs` lines 1408-1413: `None => coeffs.push(i128::MAX)`.
- Overflow values indistinguishable from real MAX values.
- **Fix**: Return error instead of sentinel.

### D. Compressor & Folding (5 findings)

**D.1 [CRITICAL] — C7 and CycloFold are completely separate circuits with no composition**
- C7DecryptAggregationCircuit (state_len=3, ExternalInputs5) vs CycloFoldStepCircuit (state_len=5, ExternalInputs3).
- Different impl blocks, different generic bounds, different recurrence relations.
- No mechanism to verify "C7 aggregation AND CycloFold ring/sigma" in one proof.
- Verifier must choose one; no cross-circuit verification exists.
- **Fix**: Design composed circuit or cross-circuit verifier challenge binding both.

**D.2 [HIGH] — FoldVerifierStepCircuit is explicit placeholder (zero real verification)**
- `fold_verifier_circuit.rs` lines 33-36: documents placeholder status.
- Constraints: `z'[0] = z[0] + 1`, `z'[1] = z[1] + ext.2`, `z'[2] = z[2] + 1`.
- Left/right accumulator hashes received but NEVER used in any constraint.
- **Fix**: Implement real fold verification or remove and document as deferred.

**D.3 [HIGH] — LatticeFoldTreeCircuitFamily has degenerate constraints (0 R1CS mults)**
- Both leaf and internal variants produce identical constraints: pure addition.
- Zero R1CS multiplication gates. Leaf and internal nodes indistinguishable.
- **Fix**: Add real tree-family constraints distinguishing leaf from internal node verification.

**D.4 [HIGH] — C7 Merkle leaf_index accepted but not enforced**
- `c7_merkle_circuit.rs` lines 130-142: documented gap.
- Merkle path always places current node at position 0 regardless of claimed leaf_index.
- **Fix**: Use leaf_index to determine correct sibling ordering in Merkle path.

**D.5 [MEDIUM] — C7 challenge derivation fully deterministic from public info**
- `r = Poseidon(commitment, dkg_root_hash)` — both public.
- Attacker can precompute all evaluations and fabricate self-consistent (share_eval, lagrange_coeff, commitment, r) tuple.
- **Fix**: Include prover randomness or verifier challenge in derivation.

### E. CLI & Infrastructure (5 findings)

**E.1 [CRITICAL] — Single-process architecture: no party isolation**
- All parties run in one process. "Malicious aggregator" is meaningless — aggregator IS the process.
- `per-node` and `per-aggregator` are profiling tools, not multi-party protocol participants.
- **Fix**: Document as prototype limitation. Production requires per-party process isolation with authenticated channels.

**E.2 [HIGH] — Partial decryption share and plaintext printed to stdout**
- `main.rs:232`: `println!("partial-decrypt: share_hex={share_hex}")` — leaks share.
- `main.rs:277`: `println!("aggregate: plaintext_hex={plaintext_hex}")` — leaks plaintext.
- **Fix**: Gate behind `--verbose` flag or `RUST_LOG=debug`.

**E.3 [MEDIUM] — No timeout on nargo/bb subprocess calls**
- `full_pipeline.rs:928-965`: five subprocess invocations with zero timeout.
- Hung/malicious binary blocks pipeline indefinitely.
- **Fix**: Wrap in `Command::new(...).timeout(Duration::from_secs(N))`.

**E.4 [MEDIUM] — `demo-seeded-rng` tripwire explicitly bypassed in demo**
- `Cargo.toml:79-80`: feature doc says "Must NOT be enabled in release/production."
- `Justfile:31`: demo enables it explicitly.
- **Fix**: Add compile-time assertion preventing `demo-seeded-rng` without explicit opt-in env var.

**E.5 [MEDIUM] — PATH-based subprocess execution**
- `Command::new("nargo")` and `Command::new("bb")` resolve from system PATH.
- PATH hijack substitutes malicious binary.
- **Fix**: Require absolute paths or verify binary hashes.

### F. External Research Insights (5 findings)

**F.1 [HIGH] — CPAD attack vulnerability**
- Checri et al. (CRYPTO 2024): partial decryption oracle enables practical key recovery.
- Requires noise flooding or NIZK proofs per share.
- PVTHFHE has committed smudging noise but CPAD resistance not formally analyzed.
- **Fix**: Document CPAD resistance claim with noise budget analysis.

**F.2 [HIGH] — Noise flooding required for IND-CPAD security**
- IND-CPA alone insufficient for threshold settings.
- Current smudging parameter σ=2^40·σ_err may or may not suffice — no formal analysis.
- **Fix**: Formal IND-CPAD reduction with current noise parameters.

**F.3 [MEDIUM] — Fiat-Shamir multi-round security loss**
- Security error grows exponentially with round count: ≈ Q^μ · ε.
- T=10 fold rounds may have higher effective soundness error than (1/3)^10.
- **Fix**: Document Fiat-Shamir security loss bound with current parameters.

**F.4 [MEDIUM] — Robust secret sharing not implemented**
- Current Lagrange interpolation accepts all shares without detecting invalid ones.
- Abort-with-blame exists but doesn't identify WHICH share is invalid (only that SOME are).
- Need cheater identification for t < n/2.
- **Fix**: Implement or document as deferred limitation.

**F.5 [LOW] — Domain separation audit**
- Protocol constants use domain tags in Noir but consistency with Rust side should be verified.
- **Fix**: Cross-reference all DOMAIN_* constants between Rust and Noir.

---

## Prioritized Remediation Plan

### Tier 0 — Immediate (breaks protocol soundness)

| ID | Finding | Effort | Demo-e2e | Per-node | Aggregator |
|----|---------|--------|----------|----------|------------|
| A.1 | Canonicalize d_commitment hash function | 0.5d | ✓ | ✓ | ✓ |
| A.2 | Extend d_commitment to bind all protocol steps | 1d | ✓ | — | ✓ |
| A.3 | Add end-to-end d_commitment verification | 0.5d | ✓ | — | ✓ |
| A.4 | Fix d_commitment circular binding | 2d | ✓ | — | ✓ |
| B.1 | Constrain participant_shares in Noir circuit | 3d | ✓ | — | ✓ |
| C.1 | Add duplicate party_id check | 0.25d | ✓ | ✓ | ✓ |
| D.1 | Compose C7 + CycloFold into single IVC chain | 5d | ✓ | — | ✓ |

### Tier 1 — High (enables active attacks)

| ID | Finding | Effort | Demo-e2e | Per-node | Aggregator |
|----|---------|--------|----------|----------|------------|
| A.5 | Absorb d_commitment into Fiat-Shamir challenges | 0.5d | ✓ | — | — |
| B.2 | Bind committee_party_ids to participant_set_hash | 0.5d | ✓ | — | ✓ |
| B.4 | Delete share_wf file or add pk_hash constraint | 0.25d | ✓ | — | — |
| C.2 | Add cryptographic binding of shares to sender | 2d | ✓ | ✓ | ✓ |
| C.3 | Restrict secret key access in party_state | 1d | ✓ | ✓ | — |
| D.2 | Implement real fold verification or document deferred | 3d | ✓ | — | ✓ |
| D.3 | Add real LatticeFoldTreeCircuitFamily constraints | 2d | ✓ | — | ✓ |
| D.4 | Enforce Merkle leaf_index in-circuit | 1d | ✓ | — | ✓ |
| E.2 | Gate stdout secret leak behind --verbose | 0.25d | ✓ | ✓ | ✓ |
| F.1 | Document CPAD resistance with formal noise analysis | 1d | — | — | — |
| F.2 | Formal IND-CPAD reduction | 2d | — | — | — |

### Tier 2 — Medium (hardening)

| ID | Finding | Effort | Demo-e2e | Per-node | Aggregator |
|----|---------|--------|----------|----------|------------|
| B.3 | Enforce threshold in interpolation | 0.5d | ✓ | — | ✓ |
| B.5 | Add party_id != 0 check in decrypt_share | 0.25d | ✓ | ✓ | — |
| C.4 | Fix Lagrange coefficient overflow | 0.5d | ✓ | — | ✓ |
| C.5 | Return error instead of i128::MAX sentinel | 0.25d | ✓ | — | ✓ |
| D.5 | Add prover randomness to C7 challenge | 0.5d | ✓ | — | ✓ |
| E.3 | Add subprocess timeouts | 0.25d | ✓ | ✓ | ✓ |
| E.4 | Add compile-time guard for demo-seeded-rng | 0.25d | ✓ | ✓ | ✓ |
| E.5 | Verify nargo/bb binary hashes | 0.5d | ✓ | ✓ | ✓ |
| F.3 | Document Fiat-Shamir security loss bound | 0.5d | — | — | — |
| F.4 | Implement robust secret sharing | 3d | ✓ | ✓ | ✓ |

### Tier 3 — Low (defense-in-depth)

| ID | Finding | Effort |
|----|---------|--------|
| B.6 | Fix e_i bound check edge case | 0.25d |
| B.7 | Document nova_state_commitment prototype status | 0.1d |
| E.1 | Document single-process architecture limitation | 0.1d |
| F.5 | Cross-reference DOMAIN_* constants Rust ↔ Noir | 0.25d |

---

## Estimated Total Effort

| Tier | Items | Effort |
|------|-------|--------|
| Tier 0 — Immediate | 7 | ~12.25 days |
| Tier 1 — High | 11 | ~13.75 days |
| Tier 2 — Medium | 10 | ~6.5 days |
| Tier 3 — Low | 4 | ~0.7 days |
| **Total** | **32** | **~33 days** |

---

## References

- Paper: `paper/main.tex`
- Threat model: `.sisyphus/design/threat-model-v1.md`
- Proof boundary: `.sisyphus/design/proof-boundary.md`
- Security docs: `SECURITY.md`, `WARNING.md`
- Architecture: `ARCHITECTURE.md`
- Meta-plan: `.sisyphus/plans/meta-plan-all-deferred.md`
- Verification gaps: `.sisyphus/plans/native-in-circuit-verification-gaps.md`
- External CPAD: Checri et al., CRYPTO 2024 (eprint 2024/116)
- External noise flooding: Boudgoust et al., 2023 (eprint 2023/016)
- External Fiat-Shamir: Klooß et al., JoC 2023

## G.9: share_wf main.nr deleted
- Date: 2026-05-18
- File removed: circuits/share_wf/src/main.nr
- Empty src/ and target/ dirs also cleaned up
- Nargo.toml and prover tomls left in place (dead artifacts, but task scope was .nr only)
- Verified: no .nr files remain under circuits/share_wf/
