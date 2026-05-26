## learnings.md

### Shamir NTT Integration (2026-05-23)

1. Thread-safety in Rayon: `self.ntt_full_shares.push()` inside a `par_iter().map()` closure caused borrow-checker error (E0596). Fixed by returning NTT shares as part of the closure result and assigning after collection.

2. IFFT with zero-padding: The original `ntt_recover_bigint` used IFFT with zeros for unknown positions, which is mathematically incorrect for partial evaluations. Fixed by implementing Lagrange interpolation using FFT domain elements.

3. NTT vs Shamir field incompatibility: `ntt_recover_bigint` operates in BN254 scalar field (Fr) using domain-element x-coordinates, while `shamir_ss.recover()` uses integer x-coordinates in the ciphertext modulus field. These produce different results — they are NOT interchangeable drop-in replacements. Step 4 (replacing Shamir recovery with NTT recovery) was reverted because the decryption shares are standard Shamir shares, not NTT-domain evaluations. The NTT shares are correctly stored (Step 3) for future verification use.

4. arkworks FFT domain: `GeneralEvaluationDomain::element(i)` returns g^i where g is the primitive root of unity. The FFT output at index i is p(g^i).

5. Lagrange interpolation in Fr: Computing p(0) from evaluations at points g^0, g^1, ..., g^{k-1} uses standard Lagrange formula with domain elements as x-coordinates.

### Build results
- `cargo test -p fhe --lib shamir_ntt`: PASSED (ntt_bigint_roundtrip)
- All 128 fhe lib tests: PASSED
- `cargo check -p pvthfhe-fhe`: compiles clean (warnings only)
- `pvthfhe-e2e --n 5 --t 2 --seed 1`: EXIT 0, all pipeline steps pass
