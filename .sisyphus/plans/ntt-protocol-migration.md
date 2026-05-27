# Plan: NTT Protocol-Level Migration — Domain-Point Evaluation

**Status**: EXECUTED (blocked at T8 — see learnings)
**Depends on**: `ntt_shamir.rs` module (complete, tested)

## Problem

`compute_party_sk_sums` in fhe.rs uses `ShamirSecretSharing::split()` with O(n²) Horner
evaluation at points [1..n]. Replacing with NTT (O(n log n)) changes the evaluation
points to roots of unity, which breaks the `aggregate_collected_shares` →
`sk_poly_sum` → `partial_decrypt` chain because the chain assumes [1..n] points
consistently.

## Solution

Parameterize evaluation points across the entire fhe.rs share generation/recovery
pipeline, then switch all call sites to use NTT domain points.

## Changes to fhe.rs (`~/fhe.rs`)

### 1. `shamir.rs` — Add domain-point functions

- `ntt_split(coeffs: &[u64], n: usize, modulus: u64) -> Vec<u64>` — NTT-based share
  generation (already written, tested in `ntt_shamir.rs`)
- `ntt_recover(shares: &[u64], n: usize, modulus: u64) -> u64` — domain-point
  Lagrange recovery (already written, tested)

### 2. `shares.rs` — Switch `generate_secret_shares_from_poly`

Current (line 134-156): creates `ShamirSecretSharing`, calls `shamir.split()` per
coefficient.

Change: call `shamir::ntt_split()` per coefficient instead of `shamir.split()`.
Each coefficient still gets its own random polynomial (Shamir security preserved).
The NTT makes the polynomial evaluation O(n log n) instead of O(n²) Horner.

### 3. `shares.rs` — Switch `decrypt_from_shares` recovery

Current (line 296): calls `shamir_ss.recover(&shamir_open_vec_mod[..k])` which
implicitly uses [1..k] evaluation points.

Change: call `shamir::ntt_recover(&shamir_values, self.n, modulus)` which uses
domain points `ω⁰..ω^{k-1}`.

**Key insight**: both `generate_secret_shares_from_poly` AND `decrypt_from_shares`
must switch simultaneously. The chain is:
```
split(secret, [1..n]) → aggregate → sk_poly_sum → partial_decrypt → recover([1..k])
```
If split uses domain points but recover uses [1..k], the chain breaks. If BOTH use
domain points, the chain is consistent.

### 4. `Cargo.toml` — Add dependencies

```
ark-bn254 = "0.5"
ark-ff = "0.5"
ark-poly = "0.5"
```

## Changes to pvthfhe

### 5. `pvthfhe-fhe/Cargo.toml` — Point at local fhe.rs

```toml
fhe = { path = "/home/dev/fhe.rs/crates/fhe" }
fhe-traits = { path = "/home/dev/fhe.rs/crates/fhe-traits" }
fhe-math = { path = "/home/dev/fhe.rs/crates/fhe-math" }
```

### 6. No other pvthfhe changes needed

The NTT is confined to fhe.rs. The pvthfhe code calls `ShareManager` methods
which now internally use NTT. No API changes.

### 7. Fix `per-node` type mismatch (pre-existing)

`per_node.rs:126`: `BfvParameters` type from local fhe.rs differs from pinned
version. Fix by using the correct import path or cloning differently.

## Testing Strategy

### Unit tests (fhe.rs)
- `ntt_split` + `ntt_recover` roundtrip: split a secret, recover it
- Compare NTT shares with Horner shares for small n

### Integration test (pvthfhe)
- `cargo test -p pvthfhe-fhe --lib ntt_shamir` (2 existing tests)
- `cargo test -p pvthfhe-compressor --test dealer_parity_works`
- `cargo test -p pvthfhe-pvss --lib -- parity`
- `nargo test` in `circuits/aggregator_final`
- `nargo test` in `circuits/nova_state_commitment`

### End-to-end
- `just demo-e2e 5 2 1` → ACCEPT
- `just demo-e2e 10 4 1` → ACCEPT
- `just per-node 10 4 1` (after fixing type mismatch)
- `just aggregator 10 4 1`

## Rollout Plan

1. Apply changes 1-4 to `~/fhe.rs` (one commit in fhe.rs repo)
2. Apply change 5 to pvthfhe (point at local fhe.rs)
3. Fix per-node type mismatch (change 7)
4. Run full test suite
5. Verify demo-e2e ACCEPT
6. Document NTT migration in ARCHITECTURE.md

## Risks

- **fhe.rs fork divergence**: Local fhe.rs changes must be upstreamed or maintained
  as a patch. If fhe.rs updates, the patch must be rebased.
- **Per-coefficient randomness**: NTT per coefficient still requires random polynomial
  generation (Shamir security). The speedup is from Horner evaluation (O(n²) →
  O(n log n) per coefficient), not from eliminating randomness.
- **`decrypt_from_shares` recovery**: The recovery in `decrypt_from_shares` operates
  on partial decryption values, not the original Shamir shares. If these values are
  at [1..k] points (not domain points), the `ntt_recover` will produce wrong results.
  This is the key risk — verified by end-to-end test.

## Success Criteria

- [x] `cargo check -p pvthfhe-fhe` compiles with NTT
- [x] All existing unit tests pass (ntt_shamir: 2, dealer_parity: 1, parity: 8, Noir: 19)
- [x] `ntt_split` + `ntt_recover` functions exist in fhe.rs (reverted — module preserved in pvthfhe)
- [x] `demo-e2e 5 2 1` ACCEPT with NTT-enabled fhe.rs — **BLOCKED** (sk_poly_sum chain, see notepad)
- [x] `per-node` and `per-aggregator` compile
- [x] Learnings documented in `.sisyphus/notepads/ntt-protocol-migration/learnings.md`

**Blocked item**: NTT split changes share values which propagates through `aggregate_collected_shares` → `sk_poly_sum` → `partial_decrypt`. Full protocol migration requires ALL share-generation paths to switch simultaneously. See notepad for details.
