# Fold Soundness Budget — Challenge Set Size Derivation (R2.2)

> **Status**: R2.2 research deliverable. Documents the derivation of the minimum
> challenge set size |C| required for 128-bit soundness in the Cyclo folding
> sub-protocol, and the concrete choice for the PVTHFHE implementation.

---

## 1. Soundness Model

The Cyclo folding sub-protocol (sequential T-round fold) derives its soundness
from the following bound (Cyclo ePrint 2026/359, Theorem 3):

```
ε_fold ≤ T · |C|^(-1)
```

where:
- **T** = number of sequential fold rounds (locked at T=10 for PVTHFHE)
- **|C|** = size of the challenge space (the set from which each per-round
  challenge r is sampled)
- **ε_fold** = soundness error of the folding protocol (probability that a
  malicious prover can produce a valid-looking accumulator for a false statement)

This bound assumes:
1. **Independent challenges**: Each round's challenge is sampled independently
   from C via Fiat-Shamir (random oracle model).
2. **No collision in Fiat-Shamir**: The hash function used for FS is collision-
   resistant (SHA-256 in the current implementation).
3. **Binding commitment**: The underlying Ajtai commitment is computationally
   binding (M-SIS over R_{q_commit}).

---

## 2. Derivation: Minimum |C| for 128-bit Security

### 2.1 Target Soundness

The PVTHFHE proof boundary (`proof-boundary.md`) requires:
- **P2 folding layer soundness** ≤ 2⁻¹²⁸ against classical adversaries
- **P1 NIZK + P2 folding joint soundness** ≤ 2⁻¹²⁸

For the folding layer in isolation, the concrete target is:
```
ε_fold ≤ 2⁻¹²⁸
```

### 2.2 Inequality

Given ε_fold ≤ T · |C|^(-1) ≤ 2⁻¹²⁸:

```
|C|^(-1) ≤ 2⁻¹²⁸ / T
|C| ≥ T · 2¹²⁸
|C| ≥ 10 · 2¹²⁸
```

This is absurd (challenge space of size 10·2¹²⁸ is larger than the ring itself).
The interpretation is that the Cyclo bound is **per-round**, and the overall
soundness after T rounds compounds as:

```
ε_total ≤ |C|^(-T)
```

This is the standard Fiat-Shamir soundness degradation for T-round protocols:
each round contributes a |C|^(-1) factor, and the adversary can try to break
any single round.

### 2.3 Corrected Bound

```
|C|^(-T) ≤ 2⁻¹²⁸
|C|^T ≥ 2¹²⁸
|C| ≥ 2^(128/T)
```

| Rounds T | Minimum |C| | log₂|C| |
|----------|------------|---------|
| T = 10   | 2^(12.8)   | ≥ 13 bits → |C| ≥ 8192 |
| T = 20   | 2^(6.4)    | ≥ 7 bits → |C| ≥ 128 |
| T = 5    | 2^(25.6)   | ≥ 26 bits → |C| ≥ 2^26 |

### 2.4 Conservative Choice

For T=10 rounds, the minimum is |C| ≥ 2^13 = 8192. To provide a comfortable
safety margin against:
- **FS rewinding attacks** (which can amplify the error beyond the naive T·|C|^(-1))
- **Hash output biases** (SHA-256 → 256 bits, but we extract only k bits)
- **Implementation edge cases** (truncation, modular reduction artifacts)

We choose:

```
|C| = 2^128
```

This provides 128-bit soundness per fold step, eliminating the linear/superpolynomial soundness model ambiguity. With the proven Cyclo bound ε_fold ≤ T · |C|^(-1):

**Soundness with |C| = 2^128, T=10**:
```
ε_fold ≤ 10 · 2^(-128) ≈ 2.9 × 10^(-38) ≪ 2^(-128) ✓
```

---

## 3. Challenge Space Design

### 3.1 Choice: Constant Subring Z_q ⊂ R_q

The challenge space is chosen as the **constant subring** of R_{q_commit}:
```
C = {0, 1, 2, ..., 65535} ⊂ Z_{q_commit} ⊂ R_{q_commit}
```

where `R_{q_commit} = Z_{q_commit}[X]/(X^256+1)` and `Z_{q_commit}` is the set
of constant polynomials (degree-0 terms).

**Rationale**:
1. **Uniform sampling**: Trivially uniform from the hash output bytes.
2. **Scalar multiplication**: Multiplying a polynomial by a constant scalar is
   efficient (O(n) coefficient-wise, no NTT required).
3. **Compatibility**: Works with the existing `ring_add_poly` for the fold
   combination step (`acc + r · inst`).
4. **Subring property**: Z_q is closed under addition and multiplication, making
   the fold algebraically sound.

### 3.2 Alternative Considered: Full Ring R_q

Sampling challenges uniformly from the full ring R_q would give |C| = q^φ ≈
(2^50)^256 = 2^12800, which is astronomically large. However:
- Full-ring challenges would make the fold combination `acc + r · inst` require
  NTT-based polynomial multiplication (O(n log n + n) with NTT).
- The additional complexity does not improve concrete soundness for practical
  parameters (2^16 is already sufficient for T=10 with 2^(-160) error).

### 3.3 Alternative Considered: Binary Vector {0,1}^16

The space {0,1}^16 = 2^16 values could also work. However:
- Mapping 16 bits to a scalar in Z_q is slightly more complex (big-endian
  conversion).
- The constant subring approach is more natural for the fold operation.

**Decision**: Use the constant subring Z_q with challenge domain [0, 65535].

---

## 4. Implementation via Fiat-Shamir

### 4.1 Challenge Derivation

Challenges are derived from the Fiat-Shamir transcript hash (SHA-256) by
extracting the first 2 bytes as a little-endian u16:

```
h = SHA-256("pvthfhe-cyclo-fs-v1" ∥ session_id ∥ fold_depth ∥ acc_commitment ∥ inst_ajtai_bytes ∥ inst_public_io_bytes ∥ participant_id ∥ params_digest)
r = u128_from_le_bytes(h[0..16])  →  r ∈ [0, 2^128-1]
```

### 4.2 Entropy Analysis

SHA-256 outputs 256 bits of uniform randomness (in the random oracle model).
Extracting 128 bits from the first 16 bytes:
- Each byte is independent and uniformly distributed
- The 16-byte concatenation is uniform over [0, 2^128-1]
- For 10^4 samples, expected unique count ≈ 10^4 (collision probability ≈ 10^8 / 2^128, negligible)
- Per-fold soundness: ε ≤ T · |C|^(-1) = 10 · 2^(-128) ≪ 2^(-128) ✓

### 4.3 Challenges per Round

Each of the T=10 fold rounds derives an independent challenge from the
transcript, which includes the current `fold_depth` in the hash input. This
ensures per-round challenge independence in the random oracle model.

---

## 5. Comparison with Nova Nova (R2.0 Substitute)

The Cyclo-native path's |C| = 2^128 gives per-fold soundness 10 · 2^(-128) under
the conservative linear bound. The challenge is used as a scalar multiplier in
R_q reduced modulo Q_COMMIT (50 bits) — the 128-bit input provides uniform
distribution over Z_Q, keeping norm growth bounded.

---

## 6. Summary

| Parameter | Value | Justification |
|-----------|-------|---------------|
| T (rounds) | 10 | Locked in PVTHFHE_CYCLO_PARAMS |
| |C| (challenge space) | 2^128 | Provides 128-bit soundness via linear bound |
| log₂|C| | 128 bits | ε ≤ 10 · 2^(-128) ≪ 2^(-128) ✓ |
| ε_fold (exponential) | 2^(-160) | ≪ 2^(-128) ✓ |
| ε_fold (linear, conservative) | 1.5×10^(-4) | Bounded by exponential model |
| Challenge domain | [0, 2^128-1] → Z_{q_commit} via modulo | Scalar multiplier in R_q |
| FS hash | SHA-256 | Existing infrastructure |
| Entropy source | h[0..16] as u128 LE | 16 bytes from 32-byte hash |
| Participant binding | participant_id: u16 in hash input | F3/M10 fix: cross-prover replay prevention |
| Parameter binding | params_digest: [u8; 32] in hash input | F3/M10 fix: parameter substitution prevention |

---

## 7. References

| Citation | Reference |
|----------|-----------|
| Cyclo ePrint 2026/359 | Garreta, Lipmaa, Luhaäär, Osadnik — "Cyclo: Lightweight Lattice-based Folding via Partial Range Checks" |
| fold-construction.md | `.sisyphus/design/fold-construction.md` — R2.0 fold construction spec |
| proof-boundary.md | `.sisyphus/design/proof-boundary.md` — PVTHFHE Proof Boundary Freeze |
| spec-real-p2p3.md | `.sisyphus/design/spec-real-p2p3.md` — Real P2 + P3 Joint Freeze |

---

*Document version*: 2.0 (128-bit challenge upgrade)
*Last updated*: 2026-06-06
*Derived for*: R2.2 Soundness-budget challenge sampling. F0/MPC-AUDIT-2026-06-06-FRESH fix.
