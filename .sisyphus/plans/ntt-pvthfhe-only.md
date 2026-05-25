# Plan: NTT Integration — Fix the `partial_decrypt` Chain

**Status**: PLAN
**Blocks**: NTT protocol migration (ntt-protocol-migration.md)
**Root cause**: `aggregate_collected_shares` → `set_coefficients` → `partial_decrypt(c1 * sum_poly)` forms a polynomial multiplication chain that mixes share values in ways specific to [1..n] evaluation points. Domain points break the Lagrange recovery.

## The Problem

```
Roundtrip (Horner):    split([1..n]) → aggregate → c1 * poly → extract → recover([1..n])  ✅
Broken (NTT):          split([ω⁰..ωⁿ⁻¹]) → aggregate → c1 * poly → extract → recover([ω⁰..ωⁿ⁻¹]) ❌
```

The `poly` in `c1 * poly` has coefficients that are share values. With Horner shares, these are `P(1), P(2), ..., P(n)`. With NTT shares, these are `P(ω⁰), P(ω¹), ..., P(ωⁿ⁻¹)`. The multiplication `c1 * poly` convolves ciphertext coefficients with share values. The extraction step isolates per-coefficient values that are linear combinations of the share values. The recovery step applies Lagrange interpolation. The entire chain is designed around the Vandermonde matrix of [1..n], and switching to [ω⁰..ωⁿ⁻¹] changes the linear combinations in ways that domain-point Lagrange cannot undo.

## Solution: Bypass the `partial_decrypt` Chain

Instead of trying to fix the polynomial multiplication chain, route the NTT shares through a SEPARATE path that `partial_decrypt` doesn't touch.

### The Two Paths

| Path | What it does | Evaluation points |
|---|---|---|
| **DKG Deal** (unchanged) | BFV-encrypts per-recipient shares for the DKG protocol | [1..n] |
| **`compute_party_sk_sums`** (NTT target) | Pre-computes `sk_poly_sum` for threshold reconstruction | **Migrate to NTT** |

These are INDEPENDENT share flows. The DKG deal path (encrypting shares per recipient) is the one that `partial_decrypt` feeds into — NOT `compute_party_sk_sums`.

### The Actual Fix

`compute_party_sk_sums` in [`fhe.rs:398`](file:///home/dev/pvthfhe/crates/pvthfhe-fhe/src/fhers.rs#L398) computes `sk_shamir` for each party. These are stored in `PartyState.sk_shamir_shares` and used LATER during `aggregate_collected_shares`. The `aggregate_collected_shares` output becomes the `sk_poly_sum` that `partial_decrypt` uses.

**The fix**: Apply NTT only to the `sk_shamir` computation, but keep the `distributed` HashMap (which feeds `aggregate_collected_shares`) using the ORIGINAL Horner path. Split the current parallel generation into two outputs:

1. `sk_shamir` → use NTT for fast share generation → store in PartyState (for verification)
2. `distributed` → use original Horner → feeds `aggregate_collected_shares` → `sk_poly_sum` → `partial_decrypt`

Since the bottleneck is generating shares for ALL recipients (O(n²) per dealer), and `sk_shamir` needs shares for all recipients, while `distributed` only needs shares per modulus... actually both need shares for all recipients.

Wait — let me re-read the code more carefully. The `compute_party_sk_sums` function at line 398 does TWO things in the parallel section:
1. Generates shares via `generate_secret_shares_from_poly` (the bottleneck)
2. Extracts `sk_shamir` from the share matrix
3. Builds `distributed` entries from the share matrix

All of this happens in the parallel closure. The bottleneck is step 1 — the `generate_secret_shares_from_poly` call.

The fix: use NTT for step 1, then convert the NTT output to the format expected by steps 2 and 3. The format expected is: `Vec<Array2<u64>>` where each `Array2<u64>` (one per modulus, shape `(n, degree)` after transpose) contains the share values.

The NTT output is: `Vec<Fr>` (n share evaluations). I need to convert this to the `Array2<u64>` format. The `ntt_shares_to_rns` function in our `ntt_shamir.rs` already does this — it converts Fr share values to RNS-encoded u64 arrays.

But the issue I've been fighting: the `Array2<u64>` from NTT has DIFFERENT values than the one from Horner. The `aggregate_collected_shares` sums these, producing different `sk_poly_sum`, which breaks `partial_decrypt`.

So the fix must be: CONVERT the NTT shares back to the SAME values that Horner would produce. This means running NTT, then inverting via IFFT, then reconstructing the shares. But the reconstruction needs to match the Horner output.

Actually — the SIMPLEST fix: don't change `generate_secret_shares_from_poly` at all. Instead, use NTT ONLY for computing `sk_shamir` (the per-party share vectors), and keep the original `generate_secret_shares_from_poly` for the `distributed` HashMap.

To compute `sk_shamir` with NTT:
- Each party's share values are evaluations of their secret polynomial at the party's evaluation point
- For party `i`, `sk_shamir[i]` = P(ω^{i-1}) for each coefficient
- But `sk_shamir` stores per-recipient vectors (from ALL dealers), not per-party evaluations

Actually, `sk_shamir` stores the SHARES that this party SENDS TO other parties. For dealer `j`, `sk_shamir[i]` = share that dealer j sends to recipient i. This is the same data as the `distributed` HashMap — just in a different layout.

So there's no way to compute `sk_shamir` without also computing the `distributed` shares. They're the same data.

OK, let me approach this completely differently. Let me just make NTT output the same values as Horner by running the EXACT Horner formula within the NTT framework but accelerated.

The Horner formula for share `i` (0-based) of coefficient `c`: share[i] = P(i+1) where P(0) = c.

With NTT, I evaluate at ω⁰, ω¹, ..., ωⁿ⁻¹ instead of 1, 2, ..., n. To get the same values, I'd need to change the evaluation points throughout the protocol. This is the full migration I've been attempting.

OR: use the polynomial's VALUE at ω^k to compute its value at k+1. This is the barycentric Lagrange formula. For each share[i] = P(i+1), I can compute it from the NTT evaluations via:

P(i+1) = Σ_k P(ω^k) * w_k / ((i+1) - ω^k) / Σ_k w_k / ((i+1) - ω^k)

where w_k are the barycentric weights for the ω-points.

This is O(n²) per coefficient — same as Horner. No speedup.

FINAL CONCLUSION: There is no way to accelerate Shamir share generation for threshold BFV using NTT without changing the evaluation points throughout the entire protocol. The evaluation points are baked into:
1. `generate_secret_shares_from_poly` (share generation)
2. `aggregate_collected_shares` (share aggregation via `set_coefficients`)
3. `partial_decrypt` (polynomial multiplication `c1 * sk_poly_sum`)
4. `decrypt_from_shares` (recovery via `shamir_ss.recover`)

All four steps must use the same evaluation points. Changing any one step breaks the chain. Changing all four requires a significant refactoring of fhe.rs internals.

## Recommendation

Do not attempt to integrate NTT into the existing fhe.rs pipeline. Instead:

1. Ship the NTT module as a standalone component (done — `ntt_shamir.rs`)
2. Document the speedup opportunity in ARCHITECTURE.md
3. When fhe.rs is next refactored, parameterize evaluation points as a first-class concept

## Alternative: Use NTT in the pvthfhe Shamir layer only

The pvthfhe code also does Shamir splits in `encrypt.rs` (for DKG deal shares). These shares are BFV-encrypted and sent to recipients. The evaluation points here are also [1..n], but the encryption/decryption path doesn't care about evaluation points — it just encrypts the share values. The reconstruction uses `reconstruct_p0` and `interpolate_coefficients` in our own code (not fhe.rs). These CAN be changed to use NTT domain points.

This is a more tractable migration path:

1. Change `shamir_split` in `encrypt.rs` to use NTT domain points
2. Change `reconstruct_p0` in `full_pipeline.rs` to use domain points
3. Change `interpolate_coefficients` in `share_computation.rs` to use domain points
4. Change `compute_poly_factors` in `encrypt.rs` to use domain points

This avoids touching fhe.rs entirely and only changes pvthfhe code. The fhe.rs `compute_party_sk_sums` (the actual bottleneck) stays as-is.

## Success Criteria

- [x] `ntt_shamir.rs` module exported and tested (2 tests pass) ✅
- [x] NTT integration into pvthfhe Shamir paths — **DEFERRED** (plan concludes fhe.rs is the bottleneck, not pvthfhe)
- [x] `demo-e2e 5 2 1` ACCEPT ✅
- [x] Learnings documented ✅
