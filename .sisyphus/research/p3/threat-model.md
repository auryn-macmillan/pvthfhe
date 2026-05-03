# P3 Threat Model: On-Chain Lattice Proof Verifier

P3 turns the frozen P2 terminal accumulator into an EVM-verifiable object. The security objective is therefore narrower than “secure the whole PVTHFHE protocol” and sharper than the P2 folding layer: P3 must preserve the inherited corruption, parameter, and Fiat-Shamir assumptions from P2 while adding the attack surface created by public calldata, transaction ordering, reorgs, contract bugs, and any trusted-setup wrapper used to make the verifier EVM-friendly.

P3 inherits the P2 security caveats from `.sisyphus/contracts/p2-to-p3-bundle.md` Section 4. In particular, the current folded object is still a surrogate rather than a retired LatticeFold+ proof, the T4 norm-bound obligation remains open, and the SHA-256 transcript/commitment layer is not itself zero-knowledge. P3 must not overclaim around those inherited limitations merely because the final verification step is executed on-chain.

## Corruption Model (inherited from P2)

- P3 carries forward the same baseline adversary from P2: a malicious PPT adversary may statically corrupt at most `t-1` of `n` parties under the honest-majority threshold regime `t = floor(n/2) + 1`.
- The adversary may also act as a public verifier-observer and as a transaction submitter on the target EVM chain or rollup, meaning it can see public inputs, proof bytes, mempool contents (when visible), and contract return values.
- P3 does **not** upgrade the baseline model to adaptive corruption, QROM Fiat-Shamir analysis, simulation-extractability, or asynchronous safety. Those remain out of scope exactly as in P2 unless a later cross-phase upgrade explicitly changes the frozen model.
- P3 also inherits the P2 notion that the accepted proof object is tied to one session via `session_id`, one ordered folded transcript via `statement_hash_chain` / `d_commitment`, and one fixed public-parameter tuple. The chain is a public verification surface, not a fresh source of protocol trust.

## P3-Specific Threats

### Malicious Prover with Chosen Ciphertexts

- **Threat:** A malicious prover chooses ciphertexts, claimed plaintext hashes, participant sets, or accumulator endpoints specifically to exploit verifier edge cases rather than to satisfy the intended folded relation.
- **Why this is new in P3:** In P2 the focus was accepting or rejecting a folded proof object off-chain; in P3 the attacker can choose inputs that maximize on-chain parser ambiguity, arithmetic corner cases, and calldata-dependent gas behavior while still presenting a superficially well-formed transaction.
- **Security consequence:** If the wrapped verifier relation fails to bind the frozen public inputs exactly, the attacker may convince the contract to accept a proof for the wrong ciphertext hash, wrong participant set, wrong epoch, or wrong terminal digest. If the wrapper omits or weakens the inherited parameter checks, P3 could silently verify a different statement than P2 produced.
- **Mitigation / requirement:** The verifier statement must bind the exact frozen P2→P3 public-input layout, including `ciphertext_hash`, `plaintext_hash`, `aggregate_pk_hash`, `dkg_root`, `epoch`, `participant_set_hash`, and terminal `d_commitment`. Session and transcript binding must survive the wrap: chosen ciphertexts are allowed, but acceptance must still imply consistency with the one frozen session and accumulator endpoint exported by P2.
- **Inherited caveat:** Because P2 still carries the surrogate status and open T4 norm-bound obligation, P3 may only claim soundness for the exact wrapped relation actually instantiated. It must not phrase chosen-ciphertext resistance as if full lattice-native soundness were already discharged upstream.

### MEV / Reorg Interaction

- **Threat:** A block builder, sequencer, proposer, or mempool observer front-runs, copies, delays, or replays a proof-submission transaction after seeing its public calldata.
- **Attack surface:** Proof bytes and public inputs are visible before inclusion on public mempools and at inclusion time on-chain. An adversary can submit the same proof first, try to censor the honest sender, or exploit short reorgs to replay a previously accepted submission on a fork.
- **Security consequence:** If P3 treats proof submission itself as a right-conferring event without replay protection, the wrong sender may obtain credit for a valid proof, or the same proof may be accepted twice across reorg boundaries or duplicated sessions. On rollups, sequencer ordering power can also degrade liveness even if soundness survives.
- **Mitigation / requirement:** Acceptance must be idempotent or explicitly nonce/session/epoch-bound. The contract should treat proof validity as bound to a unique `(session_id, epoch, participant_set_hash, d_commitment)` context rather than to “first calldata wins.” Replay after reorg should either remain harmless (same state transition, same session already finalized) or be rejected by explicit state checks. P3 security claims must distinguish soundness from liveness under MEV pressure.

### Calldata Manipulation

- **Threat:** The attacker exploits ABI decoding, truncation, length confusion, field reordering, oversized proof blobs, or malformed public inputs to trigger acceptance bugs, revert-only griefing, or excessive gas burn.
- **Why this matters on EVM:** All verifier inputs arrive as public bytes. Unlike an off-chain typed API, Solidity/Yul verifiers are exposed directly to byte-level calldata games, including malformed offsets and duplicated dynamic segments.
- **Security consequence:** A parser bug could cause the contract to verify one byte string while the application layer interprets another. Even when soundness is not broken, calldata griefing can impose denial-of-service or economic attacks by forcing expensive failed verification paths.
- **Mitigation / requirement:** The on-chain verifier must enforce exact byte lengths, exact field ordering, and exact decoding of the 200-byte public-input blob plus proof bytes. No alternate encodings, silent padding, or permissive truncation should be accepted. Failure paths should revert early where possible so malformed calldata cannot consume close to the full gas budget.

### On-Chain Verifier Bug Exploitation

- **Threat:** The adversary targets implementation defects in Solidity/Yul verifier logic or in the cryptographic wrapper contract, including missing subgroup checks, wrong field reductions, unchecked return values from precompiles, memory aliasing bugs, bad transcript hashing, or incorrect public-input wiring.
- **Security consequence:** This is the most direct path from “cryptographically valid design” to “broken deployed system.” A single verifier bug can turn an otherwise sound proof system into unconditional acceptance of invalid proofs.
- **Mitigation / requirement:** P3 must minimize handwritten arithmetic, prefer battle-tested verifier generators where possible, and treat wrapper contracts as part of the trusted computing base. Audit status from D.R.1 matters exactly because the EVM verifier bug surface dominates many theoretical differences between candidate proof systems. The frozen P2 caveats must also stay explicit here: current surrogate acceptance does not certify correctness of a future lattice-style wrapper implementation.

### Trusted Setup Ceremony Assumptions

- **Threat:** If P3 uses Groth16 or another setup-based wrapper to compress the lattice verifier relation, a compromised ceremony (“toxic waste”) can let an attacker forge accepting proofs.
- **Security consequence:** This is a new assumption relative to the lattice-native P2 story. A trusted-setup failure bypasses statement soundness even when the wrapped arithmetic relation and Solidity verifier are implemented correctly.
- **Mitigation / requirement:** The threat model must name this assumption explicitly rather than hiding it behind generic “SNARK security.” If Groth16 wrap is used, P3 soundness is conditional on a sound ceremony, correct CRS distribution, and no toxic-waste leakage. If a transparent wrapper is used instead, this threat weakens but gas/proof-size pressure may increase. The stack choice therefore trades EVM efficiency against ceremony trust.

## P2 Consistency Check

P3 is approved only if it remains a downstream preservation layer over P2 rather than a silent model change.

- inherited parameters: `q=65537`, `N=1024`, `B_e=17`
- corruption model carried forward
- ternary challenge space preserved

More concretely:

- The public statement verified by P3 must continue to refer to the same frozen parameter tuple exported by P2; P3 does not get to change modulus, ring degree, or error-bound semantics just because a wrapper proof system uses a different internal field.
- The same static malicious corruption model from P2 remains the baseline, with at most `t-1` corrupt parties under honest majority.
- The same ROM-oriented Fiat-Shamir baseline remains in force through the inherited folded proof story; P3 does not silently upgrade to QROM or stronger extractor claims.
- The same session-binding discipline remains in force through `session_id` and terminal transcript binding.
- The ternary challenge space preserved in P1 and P2 remains part of the inherited soundness story; P3 does not “wash away” that soundness profile merely by wrapping the verifier for EVM execution.
- The same caveats from the P2 bundle remain explicit: surrogate status acknowledged, T4 norm bound obligation open, and SHA-256 non-ZK caveat still present.

## VERDICT: APPROVE
