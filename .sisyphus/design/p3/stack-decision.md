# P3 Stack Decision Memo

Date: 2026-05-03
Gate: D.D.2 — P3 on-chain verifier primary + fallback decision

## Context

This memo documents the quantitative rationale for the P3 on-chain verifier stack selection, consuming the frozen parameter tuple and D.R.5 candidate scorecard as inputs.

### Frozen parameter tuple

| Parameter | Value |
| --- | --- |
| `q` | 65537 |
| `N` | 1024 |
| `B_e` | 17 |
| `FinalProof` | 32 B surrogate |
| `P3PublicInputs` | 200 B fixed |
| Gas budget | ≤ 5,000,000 |
| Proof+calldata ceiling | ≤ 14 KB |

## Candidate Scoring Summary (from D.R.5)

| Stack | Gas estimate | Calldata bytes | Proof size | Trusted-setup posture | No-EIP? | Score |
| --- | ---: | ---: | ---: | --- | --- | ---: |
| SP1 + Groth16 wrap | ~270k | ~496 | ~260 B | BN254 precompiles; existing; Groth16 ceremony | ✓ | 27 |
| Rust-in-zkVM + EVM wrap | ~250k–300k | ~500–1,104 | ~260–868 B | wrapper-dependent; existing precompiles | ✓ | 25 |
| RISC0 + Groth16 | ~250k–270k | ~480–520 | ~256 B | BN254 precompiles; existing | ✓ | 23 |
| Halo2/PSE EVM verifier | ~350k | ~1.2–1.6 KB | ~1.0–1.4 KB | KZG / BN254 | ✓ | 22 |
| Plonky3 + Groth16 wrap | ~250k–270k | ~500–540 | ~256–300 B | transparent inner, Groth16 outer | ✓ | 21 |
| MicroNova on-chain | ~2.2M | ~1.2–2.2 KB | ~1–2 KB | compression path carries setup | ✓ | 18 |
| Jolt EVM target | unshipped | unshipped | unshipped | unshipped | — | 8 |

## Primary: SP1 + Groth16 wrap

### Quantitative projections

| Metric | Estimate | Budget | Margin |
| --- | ---: | ---: | ---: |
| Verifier gas | ~270,000 | 5,000,000 | ~18.5× headroom |
| Calldata (proof only) | ~496 B | — | — |
| Proof size | ~260 B | 14,336 B (14 KB) | ~55× headroom |
| Total calldata (proof + 200 B public inputs) | ~696 B | 14,336 B | ~20× headroom |
| Prover wall-time (SP1 zkVM cycle estimate for N=1024) | ~30–120 s off-chain | no on-chain constraint | — |

### Trusted-setup posture

SP1 uses a STARK front-end internally; the EVM wrap compresses to a Groth16 proof on BN254. This introduces a one-time Groth16 trusted setup, but:
- The BN254 pairing precompiles (`ecAdd`, `ecMul`, `ecPairing`) are already live at EIP-196/197; no new EIP is needed.
- The Groth16 ceremony risk is bounded to the wrapping circuit, not to the lattice RLWE relation directly.
- This assumption is already captured in T3 and is the same posture used by Groth16-wrapped zkVMs at production scale today.

### License

SP1 uses the MIT/Apache-2 dual license for the zkVM core. The Groth16 wrapper and verification key infrastructure follow the same permissive terms. No copyleft license dependency.

### Alignment with interface spec (D.D.1)

- Consumes the 200-byte `publicInputs` blob byte-for-byte.
- Proof envelope uses `backend_id = 0x01`.
- Verifier exposes `verify(bytes calldata proof, bytes calldata publicInputs) external view returns (bool)`.
- No EIP dependency.

## Fallback: Rust-in-zkVM + Groth16/PLONK EVM wrap

### Quantitative projections

| Metric | Estimate | Budget | Margin |
| --- | ---: | ---: | ---: |
| Verifier gas | ~250k–300k | 5,000,000 | ~16–20× headroom |
| Calldata (proof only) | ~500–1,104 B | — | — |
| Proof size | ~260–868 B | 14,336 B | ~16–55× headroom |
| Total calldata (proof + 200 B public inputs) | ~700–1,304 B | 14,336 B | ~11–20× headroom |
| Prover wall-time | ~60–300 s off-chain | no on-chain constraint | — |

### Trusted-setup posture

Same Groth16/PLONK EVM wrap posture: existing BN254 precompiles, no new EIP required. Fallback preserves exact Rust semantics for the frozen upstream verifier relation and therefore does not alter the on-chain ABI or calldata layout.

### License

Depends on chosen zkVM runtime (RISC0: Apache-2 core; generic Rust-in-zkVM paths default to Apache-2 / MIT). No copyleft.

### Delivery assurance

This path is the explicit worst-case delivery route: Rust logic is not rewritten into a domain-specific circuit language; it executes inside a zkVM that compiles Rust. This maximises delivery probability when primary circuit expression or SP1-specific wrapper integration slips.

## Rollback criterion

Pivot away from the primary (SP1 + Groth16) to the fallback if **any** of the following are observed:

1. The concrete SP1 wrapped verifier gas exceeds **4,000,000** (80% of budget) once the real lattice-facing verifier relation is encoded and benchmarked on a test network.
2. Total calldata (proof + 200-byte public inputs) exceeds **12 KB** (85% of the 14 KB ceiling) after real proof generation.
3. The SP1 wrapping circuit cannot bind the frozen 200-byte public-input layout without a structural change that breaks the D.D.1 interface contract.
4. A critical security finding (CVE or audit report) is published against the SP1 Groth16 wrapper that is not patched within the P3 schedule window.
5. Any EIP dependency is introduced to the primary path that cannot be removed within one sprint.

## Non-EIP compliance

Both primary and fallback rely exclusively on `ecAdd` (EIP-196), `ecMul` (EIP-196), and `ecPairing` (EIP-197), all shipped in the Byzantium hard fork. Neither path introduces a dependency on any unshipped or speculative EIP. This satisfies the hard constraint from D.R.5 and D.D.1.

## VERDICT: APPROVE

## Primary:

**SP1 + Groth16 wrap** — ~270k gas, ~260 B proof, ~696 B total calldata, no EIP dependency, MIT/Apache-2 license, BN254 pairing precompiles only, strongest current audit posture.

## Fallback:

**Rust-in-zkVM + Groth16/PLONK EVM wrap** — ~250k–300k gas, ~260–868 B proof, ~700–1,304 B total calldata, same no-EIP posture, guaranteed delivery path via Rust-native execution in a zkVM.
