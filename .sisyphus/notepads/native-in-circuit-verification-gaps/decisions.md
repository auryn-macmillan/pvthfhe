## 2026-05-17 — Hash anchoring decisions
- decrypt_nizk_hash is computed as SHA-256 over length-delimited decrypt proof byte strings with a pvthfhe/decrypt-nizk-proofs/v1 domain prefix, then reduced to a BN254 field for Noir public input serialization.
- build_c7_prover_toml serializes public hash fields as BN254 field elements (big-endian hex) so nargo accepts them and the Solidity public input count remains field-aligned.
- HonkVerifierRealProofTest now reads proof and public_inputs artifacts from circuits/target instead of embedding stale proof bytes, keeping forge test aligned with regenerated verifier artifacts.
## 2026-05-18 — Scalar sigma decisions
- Kept sigma::verify for API compatibility, but made verify_scalar the named canonical scalar-challenge verifier.
- Used a 32-byte sign-extended scalar encoding for adapter sigma ch to match the protocol-upgrade expectation of a 32-byte challenge field while preserving ternary semantics.
- Kept the native c*z_s multiplication unchanged; only ch*s, ch*e, and ch*d are scalar coefficient-wise operations.
## 2026-05-18 — G7 compressor sigma decisions
- Fail closed for CycloFoldStepCircuit proofs without ring and sigma thread-local witnesses: legacy Track A-style tests were updated to expect verification failure.
- Norm enforcement uses 31 Boolean witnesses reconstructed against the absolute power-basis coefficient and native bound guards before allocation; this enforces bit-decomposition range membership for the witness values used in-circuit.
- The full 8192 coefficients across 3 RNS limbs are constrained for sigma equations, replacing the older 256-coefficient compressor pattern for the G7 path.

## G-LAGRANGE/G-PLAINTEXT Implementation Decisions (2026-05-18)

### Noir main() return values
- Decision: Use `fn main(...) -> pub [Field; N]` to return computed plaintext as public output
- Rationale: This makes plaintext directly visible to the verifier without trusting prover-provided values
- Alternative: Could have kept `plaintext` as pub input with constraint `plaintext == computed_plaintext`, but return values are cleaner

### ciphertext_hash binding
- Decision: Keep `ciphertext_hash` as a pub input constrained by `assert(ciphertext_hash != plaintext_hash)`
- Rationale: d_commitment already had all 8 slots filled. Adding ciphertext_hash would require changing hash function (hash_9 → hash_10), which may not be available
- Verifier still checks ciphertext_hash against bulletin board externally

### Party ID validation
- Decision: Add `assert(party_id != 0)` check in addition to `lagrange_sum == 1`
- Rationale: Lagrange sum check alone doesn't catch zero party IDs (zero ID gets λ=1, others λ=0, sum still = 1 but security broken)
- Non-zero requirement is a design constraint on committee ID assignment

### BB CLI flags
- Decision: Use `--verifier_target evm-no-zk` consistently across write_vk, prove, and write_solidity_verifier
- Rationale: BB 5.0.0-nightly.20260517 doesn't support mixing --oracle_hash and --verifier_target; verifier_target sets oracle_hash automatically
