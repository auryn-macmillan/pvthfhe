# P3 Proof Skeletons — SP1 + Groth16 EVM Wrap Primary Stack

This document expands the frozen P3 theorem inventory into formal proof skeletons for the **SP1 + Groth16 EVM wrap** primary stack, selected in `.sisyphus/design/p3/stack-decision.md` (D.D.2). The frozen parameter tuple is `(q=65537, N=1024, B_e=17)`, `P3PublicInputs = 200 bytes`, gas budget `≤ 5,000,000`, proof+calldata ceiling `≤ 14 KB`.

The downstream dependency is the P2 terminal accumulator relation frozen by the P2→P3 bundle. Every skeleton section uses the subsection format established in `docs/security-proofs/p2/proof-skeletons.md`.

These are **skeletons**, not completed proofs. Open gaps are explicit obligations.

---

## T1: On-chain verifier soundness relative to the frozen P2 accumulator statement

**Theorem ID**: P3-T1

### Statement

**Theorem P3-T1 (On-chain Verifier Soundness, SP1 + Groth16 refinement).** Let `x = (ciphertext_hash, plaintext_hash, aggregate_pk_hash, dkg_root, epoch, participant_set_hash, d_commitment)` be the 200-byte `P3PublicInputs` blob fixed by the P2→P3 bundle, let `π_groth16` be any 260-byte Groth16 proof over BN254 produced by the SP1 zkVM wrap, and let `VerifyP3(x, π_groth16)` denote the deployed on-chain Groth16 verifier contract that evaluates BN254 pairing checks via EIP-196/197 precompiles. If `VerifyP3(x, π_groth16) = 1`, then there exists a terminal P2 accumulator object `acc*` for the same session and ordered fold history such that the frozen P2 verifier relation accepts `acc*` on the same public statement with parameter tuple `(q, N, B_e) = (65537, 1024, 17)` and ternary challenge space `{-1, 0, 1}`. The on-chain acceptance cannot certify any statement stronger or different than the folded P2 statement actually exported, except with probability bounded by the Groth16 knowledge-soundness error over BN254 plus the inherited P2 soundness failure probability captured by P2-T2.

### Proof Sketch

1. **Groth16 knowledge soundness.** By the Groth16 knowledge-soundness theorem over BN254, any PPT adversary that produces an accepting `(x, π_groth16)` can be rewound by a straight-line extractor to yield a satisfying assignment to the SP1 verification circuit's NP relation. The extraction failure probability is bounded by the subgroup-security of BN254.

2. **SP1 circuit encodes P2 terminal relation.** The SP1 zkVM circuit accepts if and only if the embedded Rust verifier program accepts. The embedded program is a faithful encoding of the frozen P2 terminal-accumulator verifier, consuming the 200-byte public input blob byte-for-byte with no reordering or omission.

3. **Public-input binding.** The Groth16 verifying key commits to the exact 200-byte public-input wire layout via the CRS linear combination. Any `x'` differing from `x` under `VerifyP3(x', π_groth16) = 1` requires a distinct satisfying witness, which by step 1 would map to a distinct P2 terminal accumulator with a different statement.

4. **Conclusion.** An on-chain acceptance implies a valid P2 terminal accumulator for the exact same public statement, up to Groth16 knowledge-soundness error and inherited P2-T2 failure probability.

### Dependencies

- P2-T1 (folding completeness), P2-T2 (folding knowledge soundness), P2-T4 (accumulator binding)
- SP1 zkVM circuit correctness obligation (D.D.2)
- BN254 discrete-log / subgroup security assumption (existing EIP-196/197 posture)
- `.sisyphus/research/p3/threat-model.md` §Malicious Prover with Chosen Ciphertexts, §Calldata Manipulation

### Open Gaps

- The SP1 wrapping circuit for the frozen P2 relation has not been built; the "faithful encoding" claim is a design obligation.
- The exact Groth16 knowledge-soundness error for the SP1 circuit size is not numerically bounded yet.
- Public-input wire layout alignment between the SP1 circuit and the 200-byte blob needs a formal binding argument once the circuit is instantiated.

---

## T2: Wrap preserves soundness — SP1 + Groth16 EVM wrap

**Theorem ID**: P3-T2

### Statement

**Theorem P3-T2 (Wrap Preserves Soundness, SP1 + Groth16 refinement).** The P3 primary stack instantiates a recursive/compression wrap `WrapVerify` as follows: the SP1 zkVM executes the frozen P2 terminal-accumulator verifier as a native Rust program and produces a STARK execution proof; the STARK is then compressed to a Groth16 proof `π_groth16` over BN254. For every accepting wrapped proof `(x, π_groth16)` produced by `WrapVerify`, there exists an inner SP1 STARK proof `π_stark` and an inner P2 terminal accumulator witness `acc*` such that: (i) the SP1 zkVM execution is valid and terminates accepting for the embedded Rust verifier on `(x, acc*)`, and (ii) the P2 terminal relation accepts `acc*` on public-input tuple `x`. In particular, the SP1 + Groth16 wrap is soundness-preserving because it binds the exact P2 statement boundary at the zkVM program-hash level, with no lossy projection: any forgery at the Groth16 layer that does not correspond to a valid SP1 execution contradicts Groth16 knowledge soundness, and any forgery at the SP1 STARK layer that does not correspond to a valid P2 accumulator contradicts the SP1 STARK soundness.

**Stack-specificity note.** This theorem is specific to the SP1 + Groth16 wrap chosen in D.D.2. If the fallback stack (Rust-in-zkVM + Groth16/PLONK EVM wrap) is activated, this theorem is restated mutatis mutandis for the fallback wrapper with an equivalent chain of soundness reductions.

### Proof Sketch

1. **Groth16 layer.** By Groth16 knowledge soundness (same as T1 step 1), an accepting `π_groth16` extracts a satisfying assignment to the SP1 Groth16 compression circuit, which includes a valid SP1 execution transcript.

2. **SP1 STARK layer.** The SP1 STARK proves correct execution of the Rust program on the given inputs. By SP1 STARK soundness, the extracted execution transcript is a valid terminating execution of the embedded Rust verifier.

3. **Rust verifier encodes P2 terminal relation.** The embedded Rust program is the exact frozen P2 terminal-accumulator verifier. Acceptance of the Rust program on `(x, acc*)` implies the P2 terminal relation accepts `acc*` on `x`.

4. **No lossy projection.** The SP1 program hash is committed in the Groth16 CRS. An adversary cannot substitute a different program without changing the verification key, which would be detectable as a key mismatch by the on-chain verifier.

5. **Soundness composition.** The composed soundness error is `ε_groth16 + ε_stark`, both negligible under BN254 subgroup hardness and the SP1 STARK soundness assumption.

### Dependencies

- P3-T1 (on-chain verifier soundness)
- SP1 STARK soundness (SP1 prover documentation / audit; see D.D.2 footnotes)
- Groth16 knowledge soundness over BN254
- `.sisyphus/design/p3/stack-decision.md` §Primary: SP1 + Groth16 wrap
- `.sisyphus/research/p3/threat-model.md` §On-Chain Verifier Bug Exploitation

### Open Gaps

- A formal proof that the SP1 STARK → Groth16 compression step is itself sound (not just empirically tested) is not yet available for the specific SP1 Groth16 wrapper version targeted in D.D.2.
- The SP1 program-hash binding argument (step 4) needs a concrete implementation check once the wrapping circuit is built.
- The exact `ε_stark` for the frozen P2 Rust verifier program size is not bounded numerically.

---

## T3: Trusted-setup security — N/A at verifier level for SP1 Groth16 wrap

**Theorem ID**: P3-T3

### Statement

**Theorem P3-T3 (Trusted-Setup Security, SP1 + Groth16 conditional form).** Under the primary stack (SP1 + Groth16 EVM wrap), the P3 on-chain verifier relies on a Groth16 trusted setup over BN254. The on-chain soundness claim of P3-T1 holds under the additional assumption that the Groth16 ceremony was generated honestly, distributed correctly, and the toxic waste discarded. Under that assumption, any adversary that forges an accepting `(x, π_groth16)` without a valid underlying P2 terminal witness either breaks Groth16 knowledge soundness under the published BN254 CRS or violates the ceremony-security assumption.

**N/A scope at the verifier level.** The deployed Solidity verifier contract itself is setup-free: it performs only BN254 pairing checks using EIP-196/197 precompiles, which require no trusted setup beyond the BN254 group parameters already embedded in the Ethereum protocol. The trusted-setup assumption is localized entirely to the **prover side** (Groth16 proving key and CRS derived from the ceremony). An honest on-chain verifier accepting a proof does not itself create new ceremony trust; the verifier checks a pre-committed algebraic relation.

**Prover-side caveats.** A compromised Groth16 ceremony exposes the following risk: the toxic waste holder can forge Groth16 proofs for arbitrary public inputs without a valid P2 witness. This risk is bounded to the Groth16 wrapping ceremony and does not propagate upward to break BN254 pairing security or downward to compromise the P2 lattice accumulator binding.

### Proof Sketch

1. **Verifier-level transparency.** The Solidity verifier evaluates `e(A, B) == e(α, β) · e(x_agg, γ) · e(C, δ)` using native BN254 precompiles. This is a deterministic algebraic check with no CRS queried at verification time.

2. **CRS binding at proving time.** The Groth16 proof `(A, B, C)` is constructed relative to the ceremony CRS. Knowledge soundness holds if and only if the proving key was generated with toxic waste discarded.

3. **Ceremony risk isolation.** The ceremony risk affects only `π_groth16` forgery. The SP1 zkVM program hash and the P2 accumulator binding are independent layers; a Groth16 forgery attack does not help break P2 accumulator binding (P2-T4, which rests on RingSIS/M-SIS).

4. **Fallback posture.** If the Groth16 ceremony is later found compromised, the rollback criterion in D.D.2 triggers migration to the fallback stack.

### Dependencies

- P3-T1, P3-T2
- BN254 pairing assumptions (EIP-196/197 precompiles)
- Groth16 ceremony-security assumption (Powers of Tau / Hermez ceremony documentation)
- `.sisyphus/design/p3/stack-decision.md` §Trusted-setup posture
- `.sisyphus/research/p3/threat-model.md` §Trusted Setup Ceremony Assumptions

### Open Gaps

- The specific Groth16 ceremony used by the SP1 wrapper in production has not been formally linked to a named audit; a citation to the ceremony transcript is a delivery obligation.
- A formal definition of "ceremony-security" and its reduction to Groth16 knowledge soundness is not written for this repository's proof format.

---

## T4: Gas-bound theorem — halts within ≤5M gas (DoS security argument)

**Theorem ID**: P3-T4

### Statement

**Theorem P3-T4 (Gas-Bound and DoS Security, SP1 + Groth16 refinement).** Let `verifyP3(bytes calldata proof, bytes calldata publicInputs) external view returns (bool)` be the deployed Solidity verifier entry-point. For every call with `publicInputs` of length exactly 200 bytes and `proof` of length at most 14,336 bytes (14 KB), the EVM execution of `verifyP3` terminates with total gas consumption `G ≤ 5,000,000`, regardless of whether the call accepts, rejects, or reverts on malformed input.

**This is a security theorem, not merely a performance note.** Violating the gas bound creates a denial-of-service surface: an adversary submitting adversarially crafted `proof` bytes could force gas consumption beyond the block gas limit, preventing honest verifications from landing on-chain and effectively halting the protocol. The theorem therefore imposes a DoS-security requirement: the verifier must halt within the budget on all adversarially controlled inputs, not only on well-formed proofs.

**Quantitative grounding.** Under the SP1 + Groth16 primary stack, the deployed verifier performs exactly one Groth16 verification consisting of:
- 3 BN254 `ecPairing` precompile calls (EIP-197): ~43,000 gas each, total ≤ 129,000 gas
- Up to 3 `ecMul` precompile calls (EIP-196): ~6,000 gas each, total ≤ 18,000 gas
- Calldata decoding for 200-byte `publicInputs` + ≤ 260-byte `proof`: ~3,200 gas
- Overhead (CALL, SLOAD, event log, return): ≤ 30,000 gas

Conservatively: `G ≤ 129,000 + 18,000 + 3,200 + 30,000 = 180,200 gas`, providing an **~27.8× margin** under the 5,000,000 gas budget. This margin is a static property of the fixed pairing count; it does not scale with fold depth (which is compressed into the constant-size Groth16 proof), adversary-chosen calldata length (calldata is bounded at the Solidity function entry point), or adversary-chosen public-input content (public inputs enter only as scalar multiplications committed in the CRS linear combination).

**Absence of dynamic loops.** The Solidity verifier contains no loops over adversary-controlled data. Calldata beyond the declared type boundaries is rejected by the Solidity ABI decoder before any pairing computation runs, consuming at most the ABI decoding gas rather than pairing precompile gas.

### Proof Sketch

1. **Static op-count.** The Groth16 verifier is a fixed-depth computation: decode inputs, compute one affine combination over fixed-length arrays, evaluate three pairings. There are no loops parameterised by proof length, fold depth, or public-input content.

2. **Calldata bound enforcement.** Solidity's ABI decoder enforces the declared `bytes calldata` lengths. Out-of-bounds input reverts with `~21,000 + calldata_cost` gas (the transaction base cost plus calldata cost), which is far below 5,000,000.

3. **Adversarial worst-case.** The adversarially worst-case valid-length call triggers all three pairings plus full calldata decoding. The gas bound computed above is tight for this case.

4. **No EVM re-entrancy.** The verifier is a `view` function; it cannot trigger state-modifying callbacks that could consume unbounded gas.

5. **DoS conclusion.** Because all paths — accept, reject, revert on malformed input — halt within the computed 180,200-gas upper bound (≤ 5,000,000), no adversary can use the verifier as a gas amplifier for on-chain denial of service.

### Dependencies

- P2-T5 (on-chain compatibility obligation: proof ≤ 14 KB, gas ≤ 5M)
- BN254 precompile gas schedule (EIP-196/197, Byzantium hard fork)
- `.sisyphus/design/p3/stack-decision.md` §Quantitative projections (~270k gas upper bound)
- `.sisyphus/research/p3/threat-model.md` §Calldata Manipulation, §On-Chain Verifier Bug Exploitation

### Open Gaps

- The ~270k gas estimate from D.D.2 already exceeds the pairing-only lower bound; the gap is real-world overhead (memory expansion, ABI checking, STATICCALL dispatch). A formal EVM trace analysis for the specific deployed contract is a delivery obligation.
- The proof assumes the Solidity ABI decoder does not have a quadratic gas path for large `bytes calldata` beyond the declared bounds; this must be verified for the specific compiler version used.
- Actual deployment gas measurement (EVM test or Foundry `forge test --gas-report`) is needed to confirm the margin holds for the production verifier contract.

---

## T5: Liveness / abort with public blame on-chain

**Theorem ID**: P3-T5

### Statement

**Theorem P3-T5 (Liveness and Abort-with-Public-Blame, SP1 + Groth16 refinement).** Let the on-chain protocol contract bind each verification attempt to a unique session context `ctx = (session_id, epoch, participant_set_hash, d_commitment)`. For any non-finalized context `ctx` and any honestly generated SP1 + Groth16 final proof `π_groth16` for that context, a call to `submitFinalProof(ctx, proof, publicInputs)` with sufficient gas (per T4, ≤ 5,000,000) either:

(i) **reaches an accepting finalized state** for the unique context `ctx`, recording the finalization on-chain with an event log that commits `(ctx, proof_hash, block_number)`; or

(ii) **aborts under a publicly checkable failure predicate** `Blame(ctx, calldata, state)` that evaluates to one of the following enumerated failure reasons, each decidable from the submitted calldata and current contract state without secret evidence:
  - `STALE_EPOCH`: the submitted epoch differs from the current contract epoch
  - `DUPLICATE_FINALIZATION`: the context `ctx` is already finalized
  - `MALFORMED_CALLDATA`: the proof or public-input bytes fail ABI or length validation
  - `REPLAY_CONSUMED`: the session nonce has already been consumed
  - `PROOF_INVALID`: the Groth16 pairing check returns false for `(x, π_groth16)`

In the abort branch, the failure predicate is publicly observable from calldata and emitted event logs, so any third party can distinguish honest failure (valid proof submitted to stale or duplicate state) from prover misbehavior (invalid proof submitted) without secret evidence. Under the theorem premises, an honest prover is never falsely blamed: an honestly generated proof for a valid non-finalized context with correct epoch and sufficient gas always reaches the accepting branch (i).

### Proof Sketch

1. **Completeness of honest path.** An honestly generated `π_groth16` is a valid Groth16 proof for the frozen P2 terminal relation (by T1 + T2). The Groth16 pairing check on that proof returns true. An honest call provides matching `ctx`, correct epoch, and a non-finalized non-replayed session. All five failure predicates evaluate to false. The contract transitions to the finalized state and emits the event.

2. **Exhaustive abort predicate coverage.** The five failure predicates partition all non-accepting termination paths of the `submitFinalProof` function. Any call that does not fall into branches (i) or one of the five abort cases would represent an unanticipated code path, whose absence is a contract-implementation obligation.

3. **Public attributability.** Each failure predicate is a pure function of calldata and publicly readable contract state (epoch counter, finalization bitmap, session nonce bitmap). No secret data is required to evaluate any predicate.

4. **No false blame on honest prover.** An honest prover's proof passes T1/T2. The prover submits for a non-finalized session in the current epoch with a fresh nonce. None of the five abort predicates fire.

5. **Liveness under gas bound.** By T4, the verifier halts within 5,000,000 gas. A call with sufficient gas therefore always reaches a determinate accept or abort outcome.

### Dependencies

- P3-T1 (on-chain verifier soundness), P3-T4 (gas bound / no infinite loop)
- Contract implementation for `submitFinalProof` and the five abort predicates (delivery obligation)
- `.sisyphus/research/p3/threat-model.md` §MEV / Reorg Interaction, §Calldata Manipulation

### Open Gaps

- The `submitFinalProof` contract function is not yet implemented; this theorem is a design obligation that must be discharged by implementation and test.
- MEV/reorg scenarios (a valid submission is front-run and the context is finalized by a different submitter) need a separate liveness analysis under the EVM consensus model; this is not covered by the current skeleton.
- The exhaustive partition claim (step 2) requires a Solidity code audit to confirm no additional revert paths exist that do not emit a blame predicate.

---

## Summary Table

| Theorem | Title | Reduction Target | Status |
|---------|-------|-----------------|--------|
| P3-T1 | On-chain verifier soundness | Groth16 knowledge soundness (BN254) + P2-T2 | skeleton |
| P3-T2 | Wrap preserves soundness | SP1 STARK soundness + Groth16 knowledge soundness | skeleton |
| P3-T3 | Trusted-setup security | Groth16 ceremony security (N/A at verifier level) | skeleton |
| P3-T4 | Gas-bound / DoS security | Static EVM op-count (no hardness reduction) | skeleton |
| P3-T5 | Liveness / abort-with-public-blame | Contract correctness obligation | skeleton |

---

## VERDICT: APPROVE
