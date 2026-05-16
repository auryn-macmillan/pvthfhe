# Issues: In-Circuit Verification (G2, G3)

## Issue 1: G2 requires 8192-coeff Horner evaluation — ~1 week implementation
Private witness allocation + Horner evaluation + constraint enforcement.
See `c7_circuit.rs::generate_step_constraints` for design notes.

## Issue 2: G3 full closure blocked by fhe.rs API
`decrypt_from_shares` applies `Scaler` that converts to plaintext modulus space.
Need the pre-scaling polynomial (`result_poly` before `Scaler::new`).
Requires fhe.rs backend extension or fork.

## Issue 3: `poly_coeffs_from_bytes` returns RNS residues, not coefficients
Returns 24576 values (8192 coeffs × 3 moduli) in modulus-major layout.
Must CRT-reconstruct before polynomial evaluation.
`poly_coeffs_fr_reconstruct` added as workaround.

## Issue 4: CRT reconstruction using Fr field arithmetic is incorrect
Cannot use Fr for CRT modulo reduction because intermediate values (2^232)
exceed Fr-safe range for repeated subtraction. Must use BigInt.

## Issue 5: `crt_reconstruct_coeffs` has i128 overflow for real data
The existing method uses i128 for reconstructed coefficients but Q ≈ 2^174 > i128::MAX.
Only works for small-coefficient test data (N=2048, small messages).
