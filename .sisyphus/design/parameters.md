# Architecture B RLWE Parameters

## Scope

This note freezes the concrete RLWE/BFV parameters for Architecture B. The baseline is the Enclave secure BFV preset already aligned with the project's `N >= 8192` security floor and `gnosisguild/fhe.rs` RNS/NTT representation. Estimator evidence is recorded in `.sisyphus/design/estimator-baseline.log`.

## Security Rationale

- **Primary baseline:** Enclave secure BFV parameters (`N = 8192`, `L = 3`, `QIS` below, `t = 2^17`).
- **Estimator status:** best-effort run attempted on 2026-05-02; the host could not import `estimator`, so the transcript records the failed invocation plus the manually checked modulus facts.
- **Claim carried forward:** treat this parameter set as the project's canonical `>=128`-bit classical and `>=128`-bit PQ RLWE baseline for Architecture B, consistent with the assumptions in `.sisyphus/research/assumptions-ledger.md` and the user-mandated `>=120`-bit floor.

## Core RLWE Parameter Set

| Parameter | Value | Notes |
|---|---:|---|
| Ring dimension `N` | 8192 | Power-of-two cyclotomic ring `R_q = Z[X]/(X^N + 1, q)` |
| RNS limbs `L` | 3 | Matches Enclave secure BFV layout |
| `q_0` | 288230376173076481 | 58-bit NTT-friendly prime |
| `q_1` | 288230376167047169 | 58-bit NTT-friendly prime |
| `q_2` | 288230376161280001 | 58-bit NTT-friendly prime |
| `log2(Q)` | ~174.0000000002 | `Q = q_0 q_1 q_2` |
| Plaintext modulus `t` | 131072 (`2^17`) | Small-int / boolean compatible BFV plaintext modulus |
| Secret distribution `χ_key` | uniform ternary `{ -1, 0, 1 }` | Keygen-share secret coefficients |
| Error distribution `χ_err` | discrete Gaussian, `σ = 3.19` | Encryption and keygen error model |

## Parameter Set 1: Keygen Shares (PVSS Distribution)

| Field | Value | Notes |
|---|---:|---|
| Ring / modulus | `N = 8192`, `Q = q_0 q_1 q_2` | Same production RLWE domain as ciphertexts |
| Secret distribution | `χ_key = {-1,0,1}` | Uniform ternary secret sharing baseline |
| Error distribution | `χ_err = D_{σ=3.19}` | Same error scale as encryption |
| Packed share size | `8192 * 174 / 8 = 178,176` bytes | Theoretical packed size using the 174-bit aggregate modulus budget |
| Limb-aligned share size | `8192 * 3 * 8 = 196,608` bytes | Practical `u64`-per-limb `fhe.rs` storage cost |
| Security target | `>= 128` classical / `>= 128` PQ | Baseline inherited from the secure Enclave preset |

## Parameter Set 2: Ciphertext (BFV Encryption)

| Field | Value | Notes |
|---|---:|---|
| Ciphertext form | `ct = (c_0, c_1) in R_q^2` | Standard BFV ciphertext pair |
| Packed ciphertext size | `2 * 8192 * 174 / 8 = 356,352` bytes | Aggregate-bit accounting |
| Limb-aligned ciphertext size | `2 * 8192 * 3 * 8 = 393,216` bytes | Practical 64-bit limb representation |
| Available modulus gap | `log2(q / t) ~= 174 - 17 = 157` bits | First-order headroom before accounting for concrete noise growth |
| Security target | `>= 128` classical / `>= 128` PQ | Same RLWE hardness regime as keygen shares |

## Parameter Set 3: NTT / RNS Layout

| Limb | Prime `q_i` | Bits | `q_i mod 16384` | NTT-ready? |
|---|---:|---:|---:|---|
| `q_0` | 288230376173076481 | 58 | 1 | Yes |
| `q_1` | 288230376167047169 | 58 | 1 | Yes |
| `q_2` | 288230376161280001 | 58 | 1 | Yes |

| Layout item | Value | Notes |
|---|---:|---|
| `2N` | 16384 | Each limb satisfies `q_i == 1 mod 2N` |
| NTT size per limb | 8192 points | One negacyclic NTT per limb |
| RNS basis | `{ q_0, q_1, q_2 }` | Canonical `fhe.rs` CRT basis |
| CRT reconstruction | Garner's algorithm | Matches the required backend-representable reconstruction path |

## Estimator / Evidence Citation

- Best-effort transcript: `.sisyphus/design/estimator-baseline.log`
- Validation artifact: `.sisyphus/evidence/task-20-params.log`
- Assumption source: `.sisyphus/research/assumptions-ledger.md`

## Decision

Architecture B should use this exact parameter set as the canonical RLWE/BFV baseline for downstream noise-budget work (T21), worked examples (T23), and implementation tasks that target the `gnosisguild/fhe.rs` backend.
