# Plan: ShareManager-Side BigInt NTT Recovery

**Status**: PLAN — delegate to Sisyphus implementation agent
**Depends on**: `~/fhe.rs` fork at `/home/dev/fhe.rs`

## Approach

Store full Fr BigInt shares in `ShareManager` as a side channel, bypassing `Poly`. The BigInt shares are generated alongside u64 shares in `generate_secret_shares_from_poly` and consumed by `decrypt_from_shares` recovery. No changes to `Poly`, `fhe-math`, or any NTT arithmetic code.

## Changes to `~/fhe.rs`

### 1. `Cargo.toml` — Add dependencies
```toml
ark-bn254 = "0.5"
ark-ff = "0.5"
ark-poly = "0.5"
```

### 2. `trbfv/shamir_ntt.rs` — NTT module (new file)
- `ntt_split_bigint(coeffs, n, modulus) -> Vec<BigInt>` — full Fr evaluations
- `ntt_recover_bigint(shares, points, n, modulus) -> u64` — IFFT-based recovery
- Test: `ntt_bigint_roundtrip` (4..32, verifies split→recover)

### 3. `trbfv/mod.rs` — Register module
```rust
pub mod shamir_ntt;
```

### 4. `trbfv/shares.rs` — ShareManager changes

#### 4a. Add BigInt shares storage field
```rust
pub struct ShareManager {
    pub n: usize,
    pub threshold: usize,
    pub params: Arc<BfvParameters>,
    /// Full-precision NTT shares for recovery (BigInt per coeff per modulus per recipient)
    pub ntt_full_shares: Vec<Vec<Vec<BigInt>>>,
}
```
Each inner `Vec<BigInt>` is one coefficient's n full-precision shares.

#### 4b. Update `new()` constructor
Add `ntt_full_shares: Vec::new()`.

#### 4c. Update `generate_secret_shares_from_poly`
After the existing per-coefficient share loop, add:
```rust
// Store full-precision BigInt shares for NTT recovery
let mut bigint_shares_for_coeff = Vec::new();
for secret in &coeff_vals {
    let mut coeffs = vec![0u64; self.threshold + 1];
    coeffs[0] = secret % m;
    for k in 1..coeffs.len() { coeffs[k] = rng.gen::<u64>() % m; }
    bigint_shares_for_coeff.push(crate::trbfv::shamir_ntt::ntt_split_bigint(&coeffs, self.n, *m));
}
self.ntt_full_shares.push(bigint_shares_for_coeff);
```

#### 4d. Update `decrypt_from_shares` recovery
Replace `shamir_ss.recover(&shamir_open_vec_mod[..k])` with:
```rust
let vals: Vec<BigInt> = shamir_open_vec_mod.iter()
    .map(|(_, v)| BigInt::from(v.to_u64().unwrap_or(0)))
    .collect();
let pts: Vec<usize> = shamir_open_vec_mod.iter()
    .map(|(pidx, _)| pidx.saturating_sub(1) as usize)
    .collect();
crate::trbfv::shamir_ntt::ntt_recover_bigint(&vals, &pts, self.n, self.params.moduli[m])
```

## Changes to pvthfhe

### 5. `crates/pvthfhe-fhe/Cargo.toml`
Already pointing at local fhe.rs: `fhe = { path = "/home/dev/fhe.rs/crates/fhe" }`

### 6. No other pvthfhe changes needed
The pvthfhe code calls ShareManager methods — the BigInt shares are internal to ShareManager.

## Testing

1. `cd ~/fhe.rs && cargo test -p fhe --lib shamir_ntt` — roundtrip passes
2. `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-compressor --test dealer_parity_works`
3. `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-pvss --lib -- parity`
4. `nargo test` in `circuits/aggregator_final`
5. `PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 just demo-e2e 5 2 1` → ACCEPT

## Success Criteria

- [ ] `ntt_bigint_roundtrip` test passes in fhe.rs
- [ ] `demo-e2e 5 2 1` ACCEPT
- [ ] All existing tests pass
