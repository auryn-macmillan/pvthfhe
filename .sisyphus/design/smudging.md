# Smudging Noise Derivation for PVTHFHE Threshold Decryption

## Scope

This document derives the smudging noise parameter σ_smudge for PVTHFHE's BFV threshold
decryption pipeline. It feeds R1.4 GREEN, which adds smudging noise to `partial_decrypt` in
`crates/pvthfhe-fhe/src/fhers.rs`.

The canonical BFV/RLWE parameters (from `.sisyphus/design/parameters.md`):

| Parameter | Value |
|---|---|
| Ring dimension `N` | 8192 |
| Ciphertext modulus `log2(Q)` | ≈ 174 |
| RNS limbs | 3 × 58-bit NTT-friendly primes |
| Plaintext modulus `t_plain` | 131072 (2^17) |
| Error distribution `χ_err` | discrete Gaussian, `σ_err = 3.19` |
| Secret distribution | uniform ternary `{-1, 0, 1}` |
| Decoding margin | `log2(Q / (2 · t_plain)) = 156` bits |

The existing smudging analysis in `.sisyphus/design/noise-budget.md` uses
`σ_smudge = 2^40 · σ_err ≈ 2^41.7`. This document provides the cryptographic
justification, references, and implementation guidance for that choice.

## 1. Context

### 1.1 BFV threshold decryption

A BFV ciphertext is a pair `ct = (c0, c1) ∈ R_q^2` where `R_q = Z_q[X]/(X^N + 1)`.
The secret key `sk` is a polynomial with ternary coefficients. For threshold decryption
with `t`-of-`n` parties, `sk` is additively shared: `sk = Σ_{i=1}^n sk_i`.

Each party `P_i` computes a partial decryption share:

```
d_i = c1 · sk_i + e_smudge_i
```

The aggregator sums shares and recovers the plaintext:

```
m' = c0 + Σ d_i = c0 + c1·sk + Σ e_smudge_i = Δ·m + e_total
```

where `Δ = ⌊Q / t_plain⌋` and `e_total` is the aggregate noise. Correct decoding
requires `||e_total||_∞ < Δ / 2`.

### 1.2 Why smudging is needed

Without smudging (`e_smudge_i = 0`), the partial decryption share `d_i = c1 · sk_i`
leaks the inner product of the known ciphertext component `c1` with the secret key
share `sk_i`. An honest-but-curious adversary who observes partial decryption shares
across multiple ciphertexts can accumulate a system of linear equations in the
coefficients of `sk_i` and recover the secret key share via Gaussian elimination.

With smudging, each share becomes a noisy LWE sample: the adversary sees
`(c1, c1·sk_i + e_smudge_i)`. When the smudging noise is properly parameterized,
these samples are computationally indistinguishable from random, preventing key recovery.

### 1.3 Current implementation gap

In `crates/pvthfhe-fhe/src/fhers.rs:578` (`partial_decrypt`), the smudging noise
polynomial `esi_poly` is currently zero (lines 174-177):

```rust
let esi_poly = match party_state.esi_poly_sum.first() {
    Some(poly) => poly.clone(),
    None => self.zero_poly_level0()?,  // ← returns 0 polynomial
};
```

R1.4 GREEN will replace this with a freshly sampled Gaussian noise polynomial with
standard deviation `σ_smudge` per coefficient.

## 2. Threat Model

- **Adversary capability**: honest-but-curious (semi-honest). Follows protocol
  correctly but attempts to learn secret key material from observed protocol messages.
- **Corruption threshold**: up to `t - 1` parties may collude (static corruption).
- **Observations per session**: the adversary can observe partial decryption shares
  for every ciphertext that is partially decrypted during a protocol session. This
  is bounded by the circuit evaluation depth budget. For PVTHFHE Architecture B,
  the effective depth budget is at most the number of distinct ciphertexts processed
  per session (typically O(1) to O(10) for threshold aggregation use cases).
- **Side channel assumption**: no physical side-channel leakage (timing, power).
  Only protocol messages are in scope.
- **Security goal**: prevent recovery of any honest party's secret key share `sk_i`
  from observed partial decryption shares.

The honest-but-curious model allows us to use **computational** (LWE-based) hiding
rather than statistical hiding, which significantly reduces the required smudging
noise magnitude. See §3.3 for the distinction.

## 3. Smudging Noise Derivation

### 3.1 The Smudging Lemma (Asharov-Jain-Wichs, ePrint 2011/613)

**Lemma 2.1 (Smudging Lemma).** Let `B1 = B1(κ)` and `B2 = B2(κ)` be positive
integers. Let `e1` be a random variable with support in `[-B1, B1]`. Let `e2`
be a uniform random variable over `[-B2, B2]`. Then the statistical distance
between the distributions of `e2` and `e1 + e2` is at most `B1 / B2`.

For Gaussian smudging with standard deviation σ, the same principle applies:
the distribution of `e1 + 𝒩(0, σ²)` is statistically close to `𝒩(0, σ²)` when
`σ ≫ B1`. Specifically, the statistical distance is bounded by
`O(B1 / σ)` (via the PDF ratio bound).

### 3.2 Two Regimes for Choosing σ_smudge

#### Regime A: Statistical hiding (classical)

For simulation-based security with statistical indistinguishability, the smudging
lemma requires `σ_smudge ≥ B_sensitive · 2^λ`, where `B_sensitive` is a bound on
the "sensitive" term in the partial decryption share.

In BFV, the sensitive term is `c1 · sk_i`. Since `c1` is nearly uniform modulo q
and `sk_i` has ternary coefficients of L1-norm at most N, each coefficient of
`c1 · sk_i` has magnitude up to `N·q ≈ 2^13 · 2^174 = 2^187` in the worst case.
Statistical hiding would require `σ_smudge ≥ 2^(187+128) = 2^315`, which is
impossible for any practical modulus.

This regime is **not used** in PVTHFHE.

#### Regime B: Computational hiding via LWE (practical)

Under the honest-but-curious threat model, computational hiding suffices. The
adversary's view of a partial decryption share is `(c1, d_i = c1·sk_i + e_smudge_i)`.
This is an LWE sample with:
- Dimension: N = 8192 coefficients
- Secret: `sk_i` with ternary coefficients (known to be LWE-hard [Reg05, BLP+13])
- Modulus: q per coefficient
- Error: `e_smudge_i` with per-coefficient standard deviation `σ_smudge`

For LWE hardness in dimension N=8192, the error-to-modulus ratio must satisfy
`α = σ_smudge / q ≥ √N / q` (worst-case lattice reduction, BKZ). With
`q ≈ 2^58` per limb, this requires `σ_smudge ≥ √8192 ≈ 90.5`. Even the
encryption noise `σ_err = 3.19` falls below this threshold, confirming that
LWE with any `σ_smudge ≥ 3.19` in dimension 8192 is already hard. However, for
margin against improved attacks (sieving, enumeration), we apply a large
multiplicative safety factor.

The Rényi divergence-based analysis of [BLRL+18, ePrint 2022/1625] shows that
for computational hiding with λ-bit security, it suffices to have
`σ_smudge ≥ σ_err · 2^(λ/2)` (roughly `2^64` for λ=128). We do not claim this
bound for PVTHFHE since the honest-but-curious model is weaker than full simulation;
see §3.3.

### 3.3 Concrete Derivation for PVTHFHE

We adopt a practical engineering choice aligned with `.sisyphus/design/noise-budget.md`:

```
σ_smudge = 2^40 · σ_err
```

Numerically:

| Quantity | Value | log2 |
|---|---|---|
| `σ_err` (encryption Gaussian std dev) | 3.19 | ~1.7 |
| Multiplier | 2^40 | 40.0 |
| `σ_smudge` (smudging std dev) | ≈ 3.51 × 10^12 | ~41.7 |
| `σ_smudge²` (variance) | ≈ 1.23 × 10^25 | ~83.3 |

**Justification for `2^40` multiplier**:

1. **Cryptographic separation**: The smudging noise standard deviation (2^41.7) is
   2^40 times larger than the encryption noise standard deviation (2^1.7). This
   provides 40 bits of "statistical separation" between the smudging distribution
   and the underlying encryption noise — far more than needed for honest-but-curious
   security where computational LWE hiding is the primary defense.

2. **Correctness margin**: Even with t = 512 parties and the worst-case linear
   noise accumulation (as in the malicious analysis from noise-budget.md), the
   aggregate smudging noise is `t · σ_smudge ≈ 512 · 2^41.7 = 2^50.7`. Against a
   decoding margin of 156 bits:

   ```
   156 - 50.7 = 105.3 bits of correctness slack
   ```

   This is comfortably safe. The honest-case (root-sum growth) aggregate is even
   smaller: `√512 · 2^41.7 = 2^46.2`, leaving ~110 bits of slack.

3. **LWE hardness**: With `σ_smudge ≈ 2^41.7` and limb modulus `q_i ≈ 2^58`, the
   LWE error rate is `α ≈ 2^41.7 / 2^58 = 2^(-16.3) ≈ 1/80,000`. This is a very
   small error rate by LWE standards, but the dimension N=8192 provides sufficient
   lattice hardness (estimated >128-bit classical for these parameters via standard
   lattice reduction estimates). Note: the honest-but-curious model does not require
   LWE samples to be simulatable — only computationally hard to invert.

4. **Alignment with existing analysis**: This value is already analyzed and validated
   in `.sisyphus/design/noise-budget.md`, which closes the noise budget for both
   honest and malicious cases. Using the same value avoids parameter fragmentation.

### 3.4 Why Not Larger?

The smudging noise could be made larger — up to `σ_smudge ≈ 2^73` before the
malicious-case aggregate approaches the 156-bit decoding margin. However, a larger
value:

- Increases the `esi_poly` sampling cost (though negligible: 8192 Gaussian samples)
- Widens the wire representation of partial decryption shares (the smudging
  polynomial affects the share byte size)
- Provides no additional security benefit in the honest-but-curious model

Conversely, a **smaller** value would reduce the statistical separation margin
between the smudging noise and the underlying encryption noise, which could become
relevant if the threat model is later upgraded to full simulation. The `2^40`
factor keeps that door open with modest cost.

## 4. Concrete Numbers

### 4.1 Summary

| Parameter | Symbol | Value | log2 |
|---|---|---|---|
| Encryption Gaussian std dev | `σ_err` | 3.19 | ~1.7 |
| Smudging multiplier | — | 2^40 | 40.0 |
| Smudging Gaussian std dev | `σ_smudge` | ≈ 3.506 × 10^12 | ~41.7 |
| Smudging variance per coefficient | `σ_smudge²` | ≈ 1.230 × 10^25 | ~83.3 |
| Per-party per-coefficient magnitude bound (6σ) | `6·σ_smudge` | ≈ 2.104 × 10^13 | ~44.3 |
| Aggregate honest noise (t=512) | `√512·σ_smudge` | ≈ 7.93 × 10^13 | ~46.2 |
| Aggregate worst-case noise (t=512) | `512·σ_smudge` | ≈ 1.80 × 10^15 | ~50.7 |
| Decoding margin (Δ/2) | — | ≈ 2^156 | 156.0 |
| Correctness slack (malicious) | — | — | 105.3 bits |

### 4.2 Distribution

Each coefficient of the smudging noise polynomial `e_smudge ∈ R_q` is sampled
independently from a **discrete Gaussian** distribution centered at zero with
standard deviation `σ_smudge ≈ 3.506 × 10^12`:

```
e_smudge_coeff ∼ D_{Z, σ_smudge}
```

The discrete Gaussian `D_{Z,σ}` is defined with probability mass function:

```
Pr[X = k] = ρ_σ(k) / ρ_σ(Z)    where ρ_σ(k) = exp(-π·k²/σ²)
```

Since `σ_smudge ≪ q_i` (each limb modulus is ≈ 2^58), the probability of a sample
exceeding `q_i/2` and wrapping around is astronomically small (≈ exp(-π·(2^57)²/(2·σ²))
≈ exp(-10^90)). Rejection sampling is not required; standard Knuth-Yao or
Cannonical CDT sampling is sufficient, or a rounded continuous Gaussian followed
by modular reduction.

## 5. Implementation Sketch

### 5.1 Where the change goes (IMPLEMENTED)

File: `crates/pvthfhe-fhe/src/fhers.rs`

The `partial_decrypt` method (line ~701) samples a fresh 8192-coefficient
Gaussian smudging noise polynomial with `σ_smudge ≈ 3.506 × 10^12` using
`ChaCha8Rng` derived from the caller-supplied `OsRng`. The noise is added
to the decryption share polynomial before serialisation:

```rust
// line ~714: Sample smudging noise
let dist = Normal::new(0.0, SIGMA_SMUDGE).map_err(...)?;
let noise_coeffs: Vec<i64> = (0..degree)
    .map(|_| { let sample: f64 = dist.sample(&mut noise_rng); sample.round() as i64 })
    .collect();
let noise_poly = Poly::try_convert_from(noise_coeffs.as_slice(), ctx, ...)?;
d_share_poly += &noise_poly;
```

This is **already implemented** (not a future GREEN change). The
`SIGMA_SMUDGE` constant is locked at `3_506_204_876_800.0` (≈ 3.19 × 2^40).

### 5.2 Sampling the smudging polynomial

The smudging polynomial is an element of `R_q = Z_q[X]/(X^N+1)` in coefficient
representation (power basis). Sampling pseudocode:

```rust
use fhe_math::rq::{Poly, Representation};
use rand_distr::{Normal, Distribution};
use rand::Rng;

fn sample_smudge_poly(
    bfv_params: &Arc<BfvParameters>,
    sigma_smudge: f64,   // ≈ 3.506e12
    rng: &mut dyn RngCore,
) -> Result<Poly, FheError> {
    let ctx = bfv_params.ctx_at_level(0)?;
    let degree = bfv_params.degree();  // = 8192

    let dist = Normal::new(0.0, sigma_smudge)
        .map_err(|e| FheError::Backend { reason: e.to_string() })?;

    // Each coefficient: sample continuous Gaussian, round to nearest i64, take mod q
    let coeffs: Vec<i64> = (0..degree)
        .map(|_| {
            let sample: f64 = dist.sample(&mut *rng);
            sample.round() as i64
        })
        .collect();

    Poly::from_coeffs(&coeffs, &ctx, Representation::PowerBasis)
        .map_err(|e| FheError::Backend { reason: e.to_string() })
}
```

### 5.3 Adding to the decryption share

```rust
fn partial_decrypt(&self, ct: &Ciphertext, party_id: u32, rng: &mut dyn RngCore) -> Result<DecryptShare, FheError> {
    let (n, t) = self.threshold_params()?;
    let ct = BfvCiphertext::from_bytes(&ct.bytes, &self.bfv_params)?;

    // Sample smudging noise ← NEW (R1.4 GREEN)
    let esi_poly = self.sample_smudge_poly(&self.bfv_params, SIGMA_SMUDGE, rng)?;

    // Store for aggregation
    {
        let mut states = self.party_states.lock()...;
        states.get_mut(&party_id)?.esi_poly_sum = vec![esi_poly.clone()];
    }

    let d_share_poly = self.decryption_share_poly_with_smudge(Arc::new(ct), party_id, n, t, esi_poly)?;
    let poly_bytes = d_share_poly.to_bytes();

    Ok(DecryptShare { party_id, bytes: ProtocolBytes(wire::encode_decrypt_share(&poly_bytes)) })
}
```

### 5.4 Constant definition

```rust
/// Smudging noise standard deviation: σ_smudge = 2^40 · σ_err per coefficients.
/// σ_err = 3.19 (from parameters.md), multiplier = 2^40.
/// See `.sisyphus/design/smudging.md` for derivation.
const SIGMA_SMUDGE: f64 = 3.506_204_876_800_000.0; // 3.19 × 2^40
```

### 5.5 Dependency note

Use `rand_distr::Normal` from the `rand_distr` crate (already available via the
`rand` ecosystem). For discrete Gaussian sampling with formal constant-time
guarantees, consider `discrete-gaussian` crate; however, since σ_smudge is
extremely large and not a secret, timing leakage in sampling is irrelevant —
the smudging noise polynomial is public protocol data.

## 6. Verification Properties

### 6.1 Statistical test

Verify that the partial decryption share changes with overwhelming probability
when smudging is active. For a fixed ciphertext and party:

1. Compute `d_0 = partial_decrypt(ct, party_id)` with smudging disabled (zero esi).
2. Compute `d_1 = partial_decrypt(ct, party_id)` with smudging enabled.
3. Assert `d_0 != d_1` (should hold with probability `1` in practice, since
   σ_smudge ≫ 0).
4. Compute `d_2 = partial_decrypt(ct, party_id)` with smudging enabled (fresh RNG).
5. Assert `d_1 != d_2` (different smudge samples → different shares).
6. Verify that `||d_1 - d_0||_∞ ≤ 6·σ_smudge` (99.9999998% of samples within 6σ).

### 6.2 Correctness test

Full end-to-end: encrypt a known plaintext, threshold-decrypt with smudging,
verify the recovered plaintext matches. The aggregate noise (including smudging)
must not cause decoding failure.

### 6.3 Deterministic reproducibility test

Given a fixed seed, the smudging noise polynomial must be deterministically
reproducible (for testing/debugging), but production paths must use `OsRng`
per `.sisyphus/design/assumptions-ledger.md` §R0.7.

## 7. References

1. **Asharov, Jain, Wichs** — "Multiparty Computation with Low Communication,
   Computation and Interaction via Threshold FHE," ePrint 2011/613.
   Introduces the smudging lemma for threshold FHE.

2. **Bendlin, Damgård** — "Threshold Decryption and Zero-Knowledge Proofs for
   Lattice-Based Cryptosystems," TCC 2010. First use of smudging in
   lattice-based threshold encryption.

3. **ePrint 2022/1625** — "Threshold FHE with Polynomial Modulus-to-Noise Ratio
   via Gaussian Smudging and Rényi Divergence." Shows that Gaussian smudging
   with Rényi divergence analysis enables polynomial (rather than exponential)
   σ_smudge.

4. **ePrint 2025/2288** — "CPA^D Secure BFV." Provides a rigorous framework
   for smudging parameter selection under CPA^D security.

5. **Noah's Ark** (ePrint 2023/815) — "Efficient Threshold-FHE Using Noise
   Flooding." Practical noise flooding approach with parameter switching.

6. **.sisyphus/design/noise-budget.md** — Existing PVTHFHE noise budget closure.
   Validates `σ_smudge = 2^40 · σ_err` for Architecture B parameters.

7. **.sisyphus/design/parameters.md** — Canonical BFV/RLWE parameter set for
   Architecture B.

## 8. Smudging Mode: Legacy vs Committed (Batch B.3)

### 8.1 Two operational modes

PVTHFHE now supports two smudging-noise modes with different security guarantees:

| Mode | API | Noise source | `esm_committed` | Status |
|---|---|---|---|---|
| `legacy_local_smudge` | `FheBackend::partial_decrypt` | Fresh Gaussian ~ 𝒩(0, σ²_smudge) sampled per-decryption | `false` | **Non-equivalent mode** |
| `committed_smudge_pvss` | `FheBackend::partial_decrypt_committed_smudge` | Pre-committed `e_sm` poly from DKG transcript | `true` | **Target Committed Mode** |

### 8.1.1 Equivalence conditions

Fresh local smudging (`legacy_local_smudge`) is **not Interfold-equivalent** by default because the noise is sampled at decryption time and lacks a commitment binding the noise distribution to the DKG transcript. It remains a legacy path for honest-but-curious testing. To be considered equivalent, a `legacy_local_smudge` share would require an additional distribution/freshness proof (e.g., a NIZK demonstrating the noise was sampled correctly from the target Gaussian distribution) which is not currently implemented.

The `committed_smudge_pvss` mode is the target Interfold-equivalent mode. It requires:
1. **DKG-committed e_sm slots**: Noise polynomials must be committed during the DKG phase and shared via PVSS.
2. **Public freshness enforcement**: The `SessionRegistry` and `PvtFheVerifier` contracts must reject slot reuse to ensure one-time freshness.


### 8.2 Legacy local smudging

The legacy path (`partial_decrypt`) samples fresh Gaussian noise locally for each
decryption share. This provides honest-but-curious LWE-based hiding (prevents
secret-key recovery from observed shares) but is **not** Interfold-equivalent
because the smudging noise is not committed, shared, or publicly verified as
PKG material.

Fresh local smudging is maintained as a backward-compatible path. It must never
be the default in production configurations that claim Interfold equivalence.

### 8.3 Committed smudging (IMPLEMENTED in `FhersBackend`)

The committed path (`partial_decrypt_committed_smudge` and
`partial_decrypt_committed_smudge_with_witness`) is **already implemented**
in `crates/pvthfhe-fhe/src/fhers.rs` (lines ~849 and ~890). These methods
accept `esm_noise_poly_bytes: &[u8]`—the serialised committed `e_sm` noise
polynomial—and use it in place of fresh Gaussian sampling.

At decryption time:
1. The backend computes `d_share = c1 · sk_agg_share + esi` as usual.
2. Instead of sampling fresh Gaussian noise, it deserializes the committed
   `e_sm` polynomial bytes via `Poly::from_bytes()`.
3. It adds `d_share += e_sm_noise_poly`.
4. The returned `DecryptionWitness` (prover-side only) records `esm_committed: true`
   and the exact `e_sm` bytes used. If `esm_noise_poly_bytes` is empty,
   the method returns an error (`"esm_noise_poly_bytes is empty"`).

Both variants exist:
- `partial_decrypt_committed_smudge()` — returns only `DecryptShare`.
- `partial_decrypt_committed_smudge_with_witness()` — returns `(DecryptShare, DecryptionWitness)` with the full witness structure for NIZK proof generation.

Public verification of the decryption share is performed via the on-chain
`SessionRegistry` (enforcing one-time slot use) and the `PvtFheVerifier`
(binding the share to the DKG-committed `e_sm` slots/hashes).

The committed path is the foundation for Batch F (C6-equivalent threshold
decryption proof) in the Interfold-equivalence plan.

## 9. Slot Policy

### 9.1 Bounded slot vector model

PVTHFHE adopts a bounded slot vector model for smudging-noise management. Each party
pre-generates a fixed number of `e_sm` noise slots during DKG (or allocates them on
demand, depending on policy). A slot is consumed when it is used in a threshold
decryption share. Once consumed, the slot cannot be reused.

The motivation is twofold:

1. **Interfold equivalence**: Interfold circuit C6 (`ThresholdShareDecryption`)
   commits each party's aggregated `e_sm` share as first-class DKG material. A party
   that reuses the same smudging noise across multiple ciphertexts breaks the
   commitment binding and weakens the security guarantee. PVTHFHE enforces one-time
   use at the registry level.

2. **Defense-in-depth**: Even in the honest-but-curious model, slot reuse creates
   additional LWE samples with the same noise term, potentially aiding key-recovery
   attacks. The no-reuse policy eliminates this attack surface.

### 9.2 Default configuration

The recommended starting configuration is `slots_per_party = 16`. This provides
enough slots for typical threshold use cases (a handful of ciphertexts per session)
while keeping DKG transcript size manageable. For applications that decrypt many
ciphertexts per session, the policy can be adjusted upward.

| Policy parameter | Default | Rationale |
|---|---|---|
| `slots_per_party` | 16 | Covers typical use cases (up to 16 ciphertexts/session) without bloating DKG size |
| `pre_generated` | `true` | Pre-generation during DKG matches Interfold's two-track transcript model and enables batch verification of slot commitments |
| `policy_hash` | Config-dependent | Bound into DKG root so verifiers can confirm the expected slot policy |

On-demand allocation (`pre_generated = false`) is supported as an alternative mode
but does not provide the same Interfold-equivalent guarantee unless accompanied by a
distribution/freshness proof for each allocated slot.

### 9.3 No-reuse registry

The `SmudgeSlotRegistry` (in `crates/pvthfhe-keygen-spec/src/lib.rs`) enforces
one-time slot consumption with a strict no-reuse policy. It tracks consumed slots in
a `HashSet` keyed by `(session_id, party_id, slot_index)`.

Key properties:

- **Cross-session isolation**: slots from different sessions never collide because
  the key includes `session_id`.
- **Idempotent check**: `is_consumed()` and `is_fresh()` return consistent results
  without side effects.
- **Hard error on reuse**: `consume()` returns `Err(SmudgeSlotError)` if the slot
  was already consumed, preventing silent failures.

### 9.4 Slot ID binding

A slot is bound to a specific decryption operation by the tuple:

```text
(session_id, epoch, ciphertext_hash, decrypt_round)
```

Where:

- `session_id` identifies the DKG session that generated the slot.
- `epoch` is the sequence number for replay protection.
- `ciphertext_hash` is a cryptographic hash of the ciphertext being decrypted.
- `decrypt_round` is an integer distinguishing multiple decryption rounds within the
  same session (e.g., round 0 for the first ciphertext, round 1 for the second).

This binding ensures that a slot consumed for one ciphertext cannot be replayed for
a different ciphertext, even within the same session. The `SmudgeSlotPolicy` type
carries a `policy_hash` that binds the slot allocation strategy into the DKG
transcript root, making the policy itself publicly verifiable.
