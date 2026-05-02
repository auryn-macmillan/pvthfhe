# Noise Budget Closure for Architecture B

## Scope

This note closes the threshold-decryption noise budget for Architecture B at the T20 parameter set:

- ring dimension `N = 8192`
- ciphertext modulus `Q = q_0 q_1 q_2` with `log2(Q) ≈ 174`
- plaintext modulus `t_plain = 2^17`
- threshold `t = ⌊1024/2⌋ + 1 = 512`
- secret distribution `χ_key = {-1,0,1}`
- encryption error `χ_err = D_{σ_err}` with `σ_err = 3.19`
- smudging error `χ_smudge = D_{σ_smudge}` with `σ_smudge = 2^40 · σ_err`

We use worst-case coefficient-magnitude bounds for correctness. For honest aggregation we also record the standard independent-noise `√t` growth to show the typical honest operating point. The malicious case is re-proved with a strict linear-in-`t` bound.

## Correctness inequality

Let `Δ = Q / t_plain`. Correct decoding after threshold decryption requires the aggregate error polynomial `e_total` to stay below half the encoding gap coefficient-wise:

```text
||e_total||∞ < Δ / 2 = Q / (2 · t_plain).
```

Taking base-2 logs with the T20 parameters gives the decoding margin

```text
log2(Q / (2 · t_plain)) ≈ 174 - 1 - 17 = 156.
```

So every accepted threshold decryption must keep the final noise strictly below `2^156` in coefficient magnitude.

## 1. Encryption noise

Using the Architecture-B BFV form,

```text
ct = (c0, c1) = (b·u + e1 + Δ·m, a·u + e2).
```

The fresh encryption noise comes from the Gaussian terms `e1, e2`. For `N = 8192`,

```text
||e1||, ||e2|| ≈ σ_err · √N ≈ 3.19 · 90.5 ≈ 289.
log2(289) ≈ 8.2.
```

Thus a fresh ciphertext starts with about `2^8.2` coefficient noise, far below the `2^156` decoding limit.

## 2. Per-party partial-decryption noise

Each honest party returns

```text
d_i = c1 · sk_i + e_i^smudge.
```

The unsmudged product term is bounded by the ciphertext-noise scale times the short ternary secret scale:

```text
||c1 · sk_i|| ≈ (σ_err · √N) · √N ≈ 3.19 · N ≈ 26,000.
log2(26,000) ≈ 14.7.
```

Now choose

```text
σ_smudge = 2^40 · σ_err.
```

Numerically,

```text
log2(σ_smudge) = 40 + log2(3.19) ≈ 41.7.
```

So the accepted share noise is dominated by smudging:

```text
||d_i - c1·sk_i||∞ ≈ 2^41.7.
```

### Why this smudging parameter is valid

Two constraints have to hold simultaneously.

1. **Privacy / masking:** the smudging noise must dominate the short-secret leakage term. Here `2^41.7` is overwhelmingly larger than the intrinsic partial-decryption scale `2^14.7`, so the released share is statistically dominated by the smudging distribution rather than by the `c1·sk_i` term.
2. **Correctness:** the same smudging noise must remain far below the decoding gap `2^156`. Even after threshold aggregation, the bound stays many bits below that limit (proved below).

Hence `σ_smudge = 2^40 · σ_err` is large enough to hide the short secret relation without consuming a meaningful fraction of the BFV correctness margin.

## 3. Honest aggregation noise

Let `D = Σ_{i ∈ S} d_i` over `|S| = t = 512` honest parties. Because the smudging terms are sampled independently, the honest-case aggregate is the usual root-sum growth:

```text
||Σ e_i^smudge||∞ ≈ √t · σ_smudge.
```

At threshold,

```text
√512 · 2^41.7 = 2^4.5 · 2^41.7 = 2^46.2.
```

So the honest aggregate share noise is about `2^46.2`.

## 4. Final decryption noise and closure (honest case)

Under the sign convention in `spec-decrypt.md`, decryption forms

```text
m_noisy = c0 + D = Δ·m + e_total,
```

where the sign of the share sum is protocol-convention dependent but the magnitude bound is identical either way. The dominant term is the aggregated smudging noise, so

```text
log2(||e_total||∞) ≈ 46.2.
```

This yields two useful headroom numbers:

1. **Distance to modulus wraparound:**

   ```text
   log2(Q / 2) - log2(||e_total||∞) ≈ 173 - 46.2 = 126.8 bits.
   ```

2. **Distance to the decoding threshold `Δ/2`:**

   ```text
   156 - 46.2 = 109.8 bits.
   ```

Therefore the correctness inequality closes:

```text
2^46.2 << Q / (2 · t_plain) = 2^156.
```

The honest threshold-decryption path has more than one hundred bits of slack even after smudging.

## 5. Malicious case: up to `t-1 = 511` corrupted parties

Architecture B assumes static malicious corruption with honest majority. For a `1024`-party committee, at most `511` parties are corrupted, so at least `512 = t` parties remain honest.

There are two adversarial strategies to analyze.

### 5.1 Corrupted parties submit malformed or high-noise shares

Accepted shares must carry a decryption-share proof `π_i^{dec}` proving the RLWE relation together with shortness of the witness terms. A corrupted party cannot inject arbitrarily large accepted noise, because any such oversized witness violates the proved shortness relation and is rejected before aggregation.

So every **accepted** share is still bounded by the same shortness/smudging envelope used in the honest analysis.

### 5.2 Corrupted parties withhold shares or submit zero shares

The worst disruption for correctness is omission: corrupted parties may refuse to contribute, or send zero shares that are excluded as invalid / useless. Threshold decryption then proceeds using the `t` honest shares only. For malicious analysis we take the conservative worst-case sum bound rather than the honest `√t` average-case law:

```text
||Σ_{i=1}^t e_i^smudge||∞ ≤ t · σ_smudge.
```

At `t = 512`,

```text
512 · 2^41.7 = 2^9 · 2^41.7 = 2^50.7.
```

Thus even the strict worst-case malicious envelope satisfies

```text
2^50.7 << 2^156.
```

Equivalently, the malicious-case decoding slack is still

```text
156 - 50.7 = 105.3 bits.
```

So correctness still closes even when we pessimistically replace honest cancellation by a full linear-in-`t` bound.

## Conclusion

For the T20 parameter set, Architecture B threshold decryption is noise-safe in both regimes:

- **Honest case:** aggregate noise is about `2^46.2`, leaving `109.8` bits of decoding slack.
- **Malicious case (up to `t-1` corrupted):** conservative aggregate noise is at most `2^50.7`, leaving `105.3` bits of decoding slack.

The chosen smudging parameter `σ_smudge = 2^40 · σ_err` is therefore simultaneously:

- large enough to dominate the intrinsic `c1·sk_i` leakage term and preserve share privacy, and
- small enough that the BFV decoding inequality remains comfortably satisfied.

This closes the noise budget required by T21 for Architecture B.
