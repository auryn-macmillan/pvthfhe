# SECURITY-ADVISORY-001: Critical Cryptographic Vacuity in PVTHFHE Prototype

ADVISORY ID: SECURITY-ADVISORY-001
STATUS: DRAFT — Gated on user approval before publication
DATE: 2026-05-04
SEVERITY: CRITICAL (CVSS 10.0)
AFFECTED COMPONENTS: On-chain Verifier, Noir Circuits, Lattice Folding Implementation

## Summary
The PVTHFHE research prototype contains multiple critical vulnerabilities where cryptographic proofs and constraints are entirely bypassed or simulated. These issues render the current implementation trivially breakable, providing no security against malicious participants or external adversaries.

## Impact
An adversary can successfully submit forged or garbage proofs to the on-chain verifier, which will be accepted as valid. Furthermore, the circuit-level constraints do not verify the witness, allowing any input to generate a "valid" proof. The folding logic uses non-cryptographic hash chains instead of lattice-based commitments, making it impossible to verify the integrity of the FHE computation.

## Affected Components

### C1: Vacuous On-chain Verification
**Location:** `contracts/src/generated/HonkVerifier.sol:7` and `contracts/src/PvtFheVerifier.sol:88-99` (pre-remediation).

The original implementation of the `HonkVerifier` was vacuous, returning `true` if the keccak256 hash of the proof matched the first public input. Since the calling contract `PvtFheVerifier` (in its pre-remediation state) would set the first public input to the hash of the provided proof, any arbitrary byte array was accepted as a valid proof. This allowed an attacker to bypass all on-chain cryptographic checks.

### C2: Tautological Noir Circuits
**Location:** `circuits/micronova_wrap/src/main.nr:10-16` and `circuits/aggregator_final/src/main.nr:1-3`.

The Noir circuits used for wrapping and aggregation contained no real constraints on the public inputs. In earlier versions, they used `assert(x == x)` patterns, and currently use `assert(false)` as a killswitch. In the surrogate state, these circuits prove nothing about the witness or the computation, allowing any witness to satisfy the circuit logic if the killswitch is removed without implementing real constraints.

### C3: SHA-256 Surrogate for Lattice Folding
**Location:** `crates/pvthfhe-cyclo/src/fold.rs`.

The folding implementation, which should use LatticeFold+ over RLWE, instead uses a SHA-256 hash chain. The "Ajtai commitment" is merely `Sha256("init" || ...)` (line 58), and the "norm check" is a simple byte-maximum comparison (line 25). This is a non-cryptographic surrogate that does not provide the binding or hiding properties required for a secure lattice-based folding scheme.

## Exploit Sketch

### C1: On-chain Bypass
An attacker can bypass the on-chain verifier by following these steps:
1. Attacker prepares a `garbage_proof` consisting of random bytes.
2. Attacker calls `PvtFheVerifier.verify()` with `garbage_proof`.
3. The contract (pre-remediation) computes `publicInputs[0] = keccak256(garbage_proof)`.
4. `HonkVerifier.verify(garbage_proof, publicInputs)` returns `keccak256(garbage_proof) == publicInputs[0]`, which is always true.
5. The system accepts the random bytes as a valid proof of correct FHE computation.

### C2: Circuit Witness Forgery
A malicious prover can forge a circuit witness as follows:
1. Attacker provides any arbitrary witness data to the `micronova_wrap` circuit.
2. Because the circuit (in its surrogate state) does not constrain the relationship between witness and public inputs, the prover can generate a valid SNARK for any statement.
3. The resulting proof is "valid" but carries no semantic weight.

### C3: Folding Integrity Failure
The reliance on SHA-256 for lattice folding leads to the following integrity issues:
1. There is no algebraic link between the folded accumulator and the underlying lattice ciphertexts.
2. The norm check only looks at the maximum byte value of the witness, which has no relationship to the actual noise growth in an RLWE-based FHE scheme.
3. Challenges are derived from the first byte of a hash, which is insufficient for cryptographic soundness in a folding protocol.


## CVSS-style Severity
**AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (Score: 10.0)**

The CVSS score of 10.0 is justified by the following factors:
- **Attack Vector (Network)**: Vulnerabilities are exploitable over the network via standard contract interactions, allowing remote exploitation from anywhere in the world.
- **Complexity (Low)**: Exploitation requires no special conditions or specific environment states. For C1, any sequence of bytes is sufficient to bypass the verifier.
- **Privileges (None)**: No special permissions, accounts, or roles are required to submit a forged proof and have it accepted by the system.
- **User Interaction (None)**: No interaction from a legitimate user or administrator is needed to trigger the vulnerability.
- **Impact (High)**: The vulnerabilities cause a full compromise of integrity, as forged computation results are accepted as valid. Confidentiality is also at high risk because the threshold FHE requirements, which are meant to protect data, can be entirely bypassed.

## Mitigation
Stage 0 red-team efforts have implemented the following emergency mitigations:
- **Verifier Killswitch**: `PvtFheVerifier.sol` now unconditionally reverts with a warning message.
- **Circuit Killswitch**: `micronova_wrap` and `aggregator_final` circuits now contain `assert(false)` to prevent compilation and use.
- **Documentation**: README and source files have been updated with "DO NOT DEPLOY" banners and explicit surrogate disclosures.

## Deployment Warning
This repository is a research prototype only. Do not use this code for The Interfold or any production deployment. It is trivially breakable and provides no security. Production use must wait until Stage 1 cryptographic core remediation is complete and a sound UltraHonk verifier is implemented.

## Publication State
STATUS: DRAFT — Gated on user approval before publication.

## References
- Red-team Audit Plan: `.sisyphus/plans/redteam-stage0-killswitch.md`
- Audit Evidence: `.sisyphus/evidence/audit-report.md`
- Red-team Notepad: `.sisyphus/notepads/redteam-stage0-killswitch/`
