# P3 Theorem Inventory

This inventory freezes the theorem obligations for the P3 on-chain verifier layer that consumes the frozen P2 terminal accumulator statement and exposes it to EVM verification under the threat surface captured in `.sisyphus/research/p3/threat-model.md`.

The baseline public boundary carried from the P2→P3 bundle is:

- parameter tuple `q=65537`, `N=1024`, `B_e=17`, ternary challenge set `{-1, 0, 1}`
- `FinalProof` placeholder size: 32 bytes today
- `P3PublicInputs` size: 200 bytes (`6 × 32-byte hashes + 8-byte epoch`)
- target verifier envelope: proof size `≤ 14 KB`, verification gas `≤ 5,000,000`

## T1: On-chain verifier soundness relative to the frozen P2 accumulator statement
**Theorem ID**: P3-T1
**Assumption**: The accepted P2 terminal accumulator relation is exactly the one exported by the frozen P2→P3 bundle, and the on-chain verifier binds the full public-input tuple without reordering, omission, or silent parameter drift.
**Model**: ROM baseline inherited from P2, plus deterministic EVM execution of the deployed verifier contract.
**Dependencies**: P2-T1 (folding completeness), P2-T2 (folding knowledge soundness), P2-T4 (accumulator binding), `.sisyphus/research/p3/threat-model.md` sections `Malicious Prover with Chosen Ciphertexts` and `Calldata Manipulation`.
**Statement**: Let `x = (ciphertext_hash, plaintext_hash, aggregate_pk_hash, dkg_root, epoch, participant_set_hash, d_commitment)` be the 200-byte public-input blob fixed by the P2→P3 bundle, and let `VerifyP3(x, π)` denote the deployed on-chain verifier. If `VerifyP3(x, π) = 1`, then there exists a terminal P2 accumulator object `acc*` for the same session and ordered fold history such that the frozen P2 verifier accepts `acc*` on the same public statement, with the same parameter tuple `(q, N, B_e) = (65537, 1024, 17)` and the same ternary challenge space `{-1, 0, 1}`. Equivalently, an on-chain acceptance cannot certify any statement stronger or different than the folded P2 statement actually exported downstream, except with the inherited P2 soundness failure probability and any separately stated wrapper/setup failure captured by T2/T3.
**Status**: skeleton

## T2: Wrap preserves soundness
**Theorem ID**: P3-T2
**Assumption**: If P3 uses a recursive wrap, compression circuit, or MicroNova-style outer verifier to make the P2 relation EVM-verifiable, the wrapper circuit encodes the exact inner verifier relation and exact public-input wiring.
**Model**: Conditional wrapper theorem; N/A if no recursive or compression wrap is used.
**Dependencies**: P3-T1, `.sisyphus/research/p3/prior-art.md` wrapper rows, `.sisyphus/research/p3/threat-model.md` section `On-Chain Verifier Bug Exploitation`.
**Statement**: If P3 is instantiated through a recursive wrap `WrapVerify` around the frozen P2 verifier relation, then for every accepting wrapped proof `(x, π_wrap)` there exists an inner proof object `π_inner` such that the wrapped circuit's witness opens to `π_inner` and the underlying P2 terminal relation accepts on the same public-input tuple `x`. In particular, the wrapper is soundness-preserving only if it binds the exact P2 statement boundary rather than a lossy projection of it. If no recursive or compression wrap is used and the chain verifies the native terminal relation directly, this theorem is recorded as N/A and imposes no additional assumption beyond T1.
**Status**: skeleton

## T3: Trusted-setup security
**Theorem ID**: P3-T3
**Assumption**: Some viable P3 stacks use setup-based commitments or setup-based EVM wrappers; others may be transparent/setup-free.
**Model**: Conditional ceremony-security theorem; N/A if the chosen primary verifier path is setup-free.
**Dependencies**: `.sisyphus/research/p3/threat-model.md` section `Trusted Setup Ceremony Assumptions`, `.sisyphus/research/p3/prior-art.md` candidate-stack assumptions.
**Statement**: If the chosen P3 verifier path relies on a trusted setup, common reference string, toxic-waste-bearing ceremony, or KZG-style setup-derived verifier key, then the soundness claims of P3-T1 and P3-T2 hold only under the additional assumption that the setup was generated honestly, distributed correctly, and not later compromised. Under that branch, any adversary that forges an accepting proof without a valid underlying P2 terminal witness yields either a break of the wrapped proof system's soundness under the published CRS or a violation of the ceremony-security assumption. If the selected P3 path is transparent/setup-free, this theorem is N/A by construction and should be marked discharged without a ceremony assumption.
**Status**: skeleton

## T4: Gas-bound theorem for on-chain verification
**Theorem ID**: P3-T4
**Assumption**: The deployed verifier consumes the fixed 200-byte public-input layout, a proof blob of at most `14 KB`, and no unbounded loops over folded instance count or attacker-controlled dynamic decoding paths.
**Model**: EVM gas-cost model for the deployed verifier and its immediate wrapper logic.
**Dependencies**: P2-T5 (on-chain compatibility obligation), `.sisyphus/research/p3/threat-model.md` sections `Calldata Manipulation` and `On-Chain Verifier Bug Exploitation`, current surrogate baseline `HonkVerifier.sol: ~3M gas` from the frozen context.
**Statement**: There exists a deployed P3 verification entrypoint `verifyP3(x, π)` such that for every call with fixed-width public inputs `x` and proof bytes `π`, execution halts after consuming total gas `G(x, π) ≤ 5,000,000`, whether the call accepts, rejects, or aborts on malformed calldata. Equivalently, the verifier's effective op-count is bounded by the published 5,000,000 gas ceiling and does not scale with adversary-chosen fold depth beyond what is already compressed into the fixed final proof object. This is a security theorem, not merely a performance note: violating the gas bound would create a denial-of-service surface in which invalid or adversarial proofs can force honest users outside the allowed verification budget.
**Status**: skeleton

## T5: Liveness or abort with public blame on-chain
**Theorem ID**: P3-T5
**Assumption**: The contract state binds each verification attempt to a unique session context `(session_id, epoch, participant_set_hash, d_commitment)`, and public failure predicates are externally observable from calldata, logs, or post-state.
**Model**: Public-state liveness/blame theorem under the P3 threat model's MEV/reorg and replay assumptions.
**Dependencies**: P3-T1, P3-T4, `.sisyphus/research/p3/threat-model.md` sections `MEV / Reorg Interaction` and `Calldata Manipulation`.
**Statement**: For any non-finalized session context and any honestly generated final proof for that context, an on-chain submission with sufficient gas either (i) reaches an accepting finalized state for that unique context, or (ii) aborts under a publicly checkable predicate that identifies why the submission cannot progress, such as stale epoch/session binding, duplicate finalization, malformed calldata, replay against already-consumed state, or invalid proof bytes. In the abort branch, the failure is publicly attributable to the submitted calldata and current contract state, so third parties can distinguish honest failure from prover misbehavior without secret evidence; under the theorem premises, an honest prover is never falsely blamed by those public predicates.
**Status**: skeleton

## VERDICT: APPROVE
