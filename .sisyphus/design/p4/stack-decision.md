# P4 Stack Decision Memo

## Decision summary

We choose the **Hermine-adapted lattice PVSS stack** as the primary P4 cryptographic stack because it is the only option that leads the candidate **scorecard** on post-quantum assumptions, native public verifiability, native abort-with-blame, and linear communication. The same **scorecard** also shows that its remaining gap is narrower than the fallback candidates: BFV-key-native adaptation is still work, but it is less risky than bolting post-quantum assumptions and blame onto SCRAPE or Groth-style transcripts. This memo therefore treats the **scorecard** winner as the implementation baseline and uses the fallback only if the BFV adaptation or proof costs fail the kill criteria.

## Commitment scheme

**Choice:** Hermine-style lattice vector commitment over SIS/RLWE-friendly witness vectors, binding the dealer's secret-sharing coefficients, ciphertext randomness, and BFV-derivation auxiliaries into one public commitment root.

**Why this wins on the scorecard:**

- **Assumption:** the scorecard gives Hermine 5/5 because the commitment lives in the same post-quantum lattice world as the rest of the protocol; Pedersen/Feldman-style commitments would immediately lose the assumption dimension.
- **Public Verifiability:** the commitment is designed to feed public transcript checks, matching Hermine's 5/5 public-verifiability score rather than forcing private complaint logic.
- **Abort-with-Blame:** the commitment is what makes malformed ciphertexts and inconsistent openings attributable in public, supporting the 5/5 blame score.
- **BFV Integration:** the scorecard already rates Hermine 4/5 here because the witness is structurally closer to RLWE/BFV key material than classical discrete-log commitments.
- **Implementation Risk:** we accept the 3/5 implementation-risk score because adapting one lattice commitment layer is still lower risk than translating between unrelated algebraic objects later.

## NIZK / ZK stack for share validity

**Choice:** a Hermine-native lattice NIZK proving (1) witness smallness, (2) ciphertext/commitment consistency, and (3) correctness of the BFV-key-coupled share relation, instantiated as a Fiat-Shamir transcript in Rust.

This is the stack that directly addresses **P4-T3 (public verifiability soundness)**: the verifier must accept dealer transcripts only when the encrypted shares, committed witness, and BFV-derivation statement are jointly consistent. We therefore do **not** choose a generic discrete-log NIZK or a pairing SNARK as the primary proof layer, because that would give back the scorecard's advantage on assumptions and would widen the soundness adaptation gap called out in the novelty memo.

**Why this wins on the scorecard:**

- **Public Verifiability:** native public proof objects preserve the scorecard's 5/5 rating instead of retrofitting a secondary proof layer.
- **Abort-with-Blame:** invalid dealer or opener behavior fails against public proof checks, preserving Hermine's 5/5 blame path.
- **Communication:** one batched lattice proof per dealer keeps the O(n) publication discipline that earned the 5/5 communication score.
- **Implementation Risk:** this is the main reason Hermine is only 3/5 on risk, but the scorecard still ranks it above all alternatives because every fallback adds even more adaptation layers.

## Hash-to-group / challenge derivation

**Choice:** use `sha3`'s **SHAKE256** as the primary domain-separated hash-to-ring / Fiat-Shamir challenge generator, and `sha2`'s **SHA-256** for fixed-length transcript digests and wire-level commitment identifiers.

The task asks for hash-to-group; in the Hermine-adapted lattice setting this is better interpreted as **hash-to-ring / challenge derivation**, because the protocol is not centered on prime-order group elements. SHAKE256 is the better primary choice for lattice-friendly challenge expansion and transcript squeezing, while SHA-256 remains a practical fixed-width digest for `transcript_root`, `proof_ref`, and external serialization boundaries already frozen in the interface spec.

**Why this wins on the scorecard:**

- **Assumption / BFV Integration:** SHAKE256 aligns better with lattice transcript practice and avoids introducing a discrete-log flavored hash abstraction solely for legacy PVSS compatibility.
- **Implementation Risk:** pairing a conservative SHA-256 digest path with SHAKE256 challenge expansion reduces integration risk while keeping the Hermine assumptions intact.

## Rust crates

**Pinned choices:**

- `serde = "1.0.228"` — frozen wire encoding for `KeygenSession`, `Share`, `PublicVerificationArtifact`, `BlameProof`, and `BFVPublicKey`.
- `serde_json = "1.0.145"` — JSON transcript and KAT fixture encoding matching the frozen interface spec.
- `sha2 = "0.10.9"` — SHA-256 transcript digests and stable wire-level commitment/root hashing.
- `sha3 = "0.10.8"` — SHAKE256 challenge derivation and lattice-friendly transcript expansion.
- `merlin = "3.0.0"` — Fiat-Shamir transcript engine for the native Rust NIZK implementation.
- `risc0-zkvm = "2.1.0"` — first zkVM fallback when the native lattice verifier/prover cannot be expressed in a succinct proof system quickly enough.
- `sp1-sdk = "5.0.0"` — second zkVM fallback to keep proving-stack optionality, consistent with the recorded decision that Noir must not block progress.

We intentionally keep the lattice proof logic in-tree instead of pretending an off-the-shelf crate already implements the full Hermine witness relation. The crate choices above minimize glue code around the already-frozen serde interface while keeping the scorecard's assumption, public-verifiability, and BFV-integration advantages intact.

## Proof system / zkVM fallback

**Primary proof system:** Hermine's native lattice proof-of-smallness / linear-relation NIZK, compiled as a Rust prover/verifier using Merlin + SHAKE256 Fiat-Shamir.

**Reasoning:** this keeps the proof system inside the same algebraic world as the commitment and ciphertext relation, which is exactly why the scorecard ranks Hermine above the classical alternatives. A pairing SNARK or classical Sigma layer would lower the assumption score and create the cross-algebra soundness gap that the scorecard kill criteria already warn about.

**Fallback:** if the chosen proof system cannot efficiently prove the lattice NIZK statement needed for P4-T3 and public share-validity checks, we fall back to running the **same Rust prover** inside a **RISC Zero** or **SP1** zkVM. That fallback is explicitly acceptable under the recorded project decisions: proving stack is unrestricted, Noir is not a blocker, and Rust-in-zkVM is an approved escape hatch.

**Fallback trigger conditions:**

1. native lattice proofs fail to preserve public-verifiability soundness for the BFV-coupled statement,
2. concrete prover/verifier costs miss the 1024-party budget even after batching, or
3. implementing the native verifier would add more risk than wrapping the Rust reference prover in RISC Zero or SP1.

## Final recommendation

Implement P4 around the Hermine-adapted lattice commitment + native lattice NIZK + SHAKE256/SHA-256 transcript stack, with serde-based wire types and Merlin transcripts in Rust. Keep RISC Zero and SP1 pinned as explicit zkVM fallbacks so the proof-system choice cannot block the BFV-coupled, publicly verifiable, abort-with-blame design that won the candidate scorecard.
