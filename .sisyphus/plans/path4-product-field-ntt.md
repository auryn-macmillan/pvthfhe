# Plan: Path 4 — Product-Field NTT for Shamir Shares

**Status**: PLAN
**Blocks**: NTT protocol migration
**Key insight**: The product of BFV moduli (~180 bits) fits in BN254 Fr (254 bits), so NTT arithmetic is exact. No precision loss.

## Problem Summary

The current `generate_secret_shares_from_poly` in fhe.rs does O(n²) Horner evaluation
per coefficient, per modulus. With `degree=8192`, `n=64`, `moduli=3`, the total work
is `3 × 8192 × 64² ≈ 100M ops`. This takes ~44s per dealer at n=64.

The product-field NTT replaces the per-modulus Horner with a single FFT/IFFT roundtrip
over BN254 Fr, evaluating ALL coefficients at ALL n domain points simultaneously.

## Approach

Currently, `generate_secret_shares_from_poly` iterates over moduli and for each modulus,
iterates over coefficients, calling `shamir.split()` which uses Horner at [1..n].

The fix: replace the inner per-coefficient loop with NTT batch evaluation using the
PRODUCT of all moduli as the Shamir modulus.

### Why This Works

- BFV moduli are ~60-bit primes: e.g. `0x3fffffff000001`
- Product of 3 moduli ≈ 180 bits
- BN254 Fr modulus ≈ 254 bits
- Product modulus < Fr modulus → no wraparound during NTT arithmetic

### The Change

In `generate_secret_shares_from_poly`, for each modulus `m`:
```
Before: for each coeff c: shamir.split(c, n, m) → O(n²) Horner per coeff
After:  run NTT once → O(n log n) for ALL coefficients → reduce mod m per evaluation
```

## Changes to fhe.rs (`~/fhe.rs`)

### 1. `shamir_ntt.rs` — NTT utility functions

Already created in the fork. Functions needed:
- `ntt_split(coeffs: &[u64], n: usize, modulus: u64) -> Vec<u64>` — exists
- `ntt_recover_with_points(...)` — exists (Lagrange in BigInt mod m)

### 2. `shares.rs` — `generate_secret_shares_from_poly`

Replace the per-coefficient `shamir.split()` loop with NTT batch evaluation:

```rust
// For each modulus m:
//   Step 1: Collect ALL coefficients, build polynomial in Fr
//   Step 2: NTT evaluate at domain points → n shares per coefficient
//   Step 3: Reduce each share modulo m
//   Step 4: Populate m_data in the same format as before

let mut rng = ChaCha20Rng::seed_from_u64(seeds[i]);
let mut m_data: Vec<u64> = Vec::with_capacity(self.params.degree() * self.n);

// Collect coefficient values for this modulus
let coeff_vals: Vec<u64> = p.iter().map(|c| c.to_u64().unwrap_or(0) % *m).collect();

// For each coefficient (treated as secret), generate NTT shares
for secret in &coeff_vals {
    let mut coeffs = vec![0u64; self.threshold + 1];
    coeffs[0] = secret;
    for k in 1..coeffs.len() { coeffs[k] = rng.gen::<u64>() % *m; }
    m_data.extend_from_slice(&crate::trbfv::shamir_ntt::ntt_split(&coeffs, self.n, *m));
}
```

**Each coefficient still gets its own random polynomial** (Shamir security preserved).
The NTT replaces Horner for the polynomial evaluation step.

### 3. `shares.rs` — `decrypt_from_shares` recovery

Replace `shamir_ss.recover()` with `ntt_recover_with_points()`:

```rust
// Before: shamir_ss.recover(&shamir_open_vec_mod[..k])
// After: ntt_recover_with_points(vals, pts, n, modulus)
```

`pts` are `party_idx - 1` (0-based domain indices).
`vals` are the coefficient values from decryption shares.

Both must switch simultaneously — the plan gates on demo-e2e ACCEPT to verify.

### 4. `Cargo.toml` — Dependencies

Already in the fork: `ark-bn254`, `ark-ff`, `ark-poly`.

## Changes to pvthfhe

### 5. `Cargo.toml` — Point at local fhe.rs

```toml
fhe = { path = "/home/dev/fhe.rs/crates/fhe" }
```

Plus `[patch]` section in workspace Cargo.toml for transitive deps.

### 6. No other pvthfhe changes

The NTT is confined to fhe.rs. The pvthfhe code calls ShareManager methods
which internally use NTT. No API changes.

## Testing Strategy

### Unit tests (fhe.rs)
- `ntt_split` + `ntt_recover_with_points` roundtrip (already implemented, needs fix)
- Compare NTT shares with Horner shares for small n

### Integration tests (pvthfhe)
- `dealer_parity_works`
- `ntt_shamir` (2 tests)
- Parity tests (8 tests)
- Noir aggregator_final (12 tests)
- Noir nova_state_commitment (7 tests)

### End-to-end
- `demo-e2e 5 2 1` → ACCEPT
- `demo-e2e 10 4 1` → ACCEPT
- `demo-e2e 64 31 1` → ACCEPT (verify speedup)

## Rollout Plan

1. Fix `ntt_recover_with_points` roundtrip test in fhe.rs (currently failing)
2. Apply changes 2-3 to `shares.rs` (split + recover)
3. Point pvthfhe at local fhe.rs (change 5)
4. Build all crates
5. Run full test suite
6. Run demo-e2e 5 2 1 → verify ACCEPT
7. Run demo-e2e 64 31 1 → verify speedup vs baseline 47 min

## Risks

- **Per-coefficient randomness still needed**: Each coefficient gets independent randomness.
  The NTT just replaces Horner evaluation. Same security level.
- **ntt_recover_with_points correctness**: Must pass the roundtrip test first. The Lagrange
  interpolation must be computed modulo the BFV modulus (not BN254 Fr). Fix verified by
  roundtrip test before proceeding to shares.rs changes.
- **decrypt_from_shares correctness**: Gate on demo-e2e ACCEPT. If recovery and split
  both use domain points, the chain should be consistent.

## Success Criteria

- [ ] `ntt_split` + `ntt_recover_with_points` roundtrip test passes (fhe.rs)
- [ ] `demo-e2e 5 2 1` ACCEPT
- [ ] `demo-e2e 64 31 1` ACCEPT with measurable speedup vs 47-min baseline
- [ ] All existing tests pass
