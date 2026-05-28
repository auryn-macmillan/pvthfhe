#![cfg(feature = "legacy-nova")]
//! G1 RED tests: RingVerifierCircuit in-circuit ring equation verification.
//!
//! Verifies that the Cyclo ring equation is correctly encoded as R1CS
//! constraints inside RingVerifierCircuit, closing trust gap G1.
//!
//! Key: Ternary challenge c ∈ {-1, 0, 1}. Each test creates a circuit
//! with honest ring elements and verifies that:
//!   1. Honest witnesses satisfy all constraints
//!   2. Tampered witnesses fail constraint checks
//!   3. Wrong challenge breaks the equation
//!   4. Hash mismatches are detected

use ark_bn254::Fr;
use ark_ff::{One, Zero};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::ConstraintSystem;
use folding_schemes::frontend::FCircuit; // folding (legacy-nova)
use pvthfhe_compressor::nova::poseidon_gadget::hash256_native;
use pvthfhe_compressor::nova::ring_verifier::RingVerifierCircuit;
use pvthfhe_compressor::nova::RingEqExternalInputs5;
use pvthfhe_compressor::nova::RingEqExternalInputs5Var;

/// Build honest ring elements for N=256 where c=1 equation holds.
/// zs[k] + ze[k] == t[k] + d[k] for all k.
fn honest_ring_coeffs_c1() -> (Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>) {
    let n = 256;
    let mut zs = vec![Fr::zero(); n];
    let mut ze = vec![Fr::zero(); n];
    let mut t = vec![Fr::zero(); n];
    let mut d = vec![Fr::zero(); n];
    for k in 0..n {
        zs[k] = Fr::from((k + 5) as u64);
        ze[k] = Fr::from((k + 15) as u64);
        t[k] = Fr::from((k + 3) as u64);
        d[k] = Fr::from((k + 17) as u64); // zs+ze = 2k+20 = t+d = (k+3)+(k+17)
    }
    (zs, ze, t, d)
}

/// Build honest ring elements for N=256 where c=-1 equation holds.
/// d[k] + ze[k] == t[k] + zs[k] for all k.
fn honest_ring_coeffs_cm1() -> (Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>) {
    let n = 256;
    let mut zs = vec![Fr::zero(); n];
    let mut ze = vec![Fr::zero(); n];
    let mut t = vec![Fr::zero(); n];
    let mut d = vec![Fr::zero(); n];
    for k in 0..n {
        zs[k] = Fr::from((k + 3) as u64);
        ze[k] = Fr::from((k + 9) as u64);
        // For c=-1: d + ze = t + zs  →  d + (k+9) = t + (k+3)
        // Pick t = k+10, d = k+4  →  (k+4)+(k+9) = 2k+13, (k+10)+(k+3) = 2k+13 ✓
        t[k] = Fr::from((k + 10) as u64);
        d[k] = Fr::from((k + 4) as u64);
    }
    (zs, ze, t, d)
}

/// Build honest ring elements for N=256 where c=0 equation holds.
/// ze[k] == t[k] for all k.
fn honest_ring_coeffs_c0() -> (Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>) {
    let n = 256;
    let mut zs = vec![Fr::zero(); n];
    let mut ze = vec![Fr::zero(); n];
    let mut t = vec![Fr::zero(); n];
    let mut d = vec![Fr::zero(); n];
    for k in 0..n {
        zs[k] = Fr::from((k * 7 + 1) as u64); // arbitrary, ignored by c=0
        ze[k] = Fr::from((k + 5) as u64);
        t[k] = Fr::from((k + 5) as u64); // must equal ze[k]
        d[k] = Fr::from((k * 3) as u64); // arbitrary, ignored by c=0
    }
    (zs, ze, t, d)
}

/// Compute 4 Poseidon hashes for the 4 ring elements (each 256 coefficients).
fn compute_hashes(zs: &[Fr], ze: &[Fr], t: &[Fr], d: &[Fr]) -> (Fr, Fr, Fr, Fr) {
    let zs_hash = hash256_native(zs);
    let ze_hash = hash256_native(ze);
    let t_hash = hash256_native(t);
    let d_hash = hash256_native(d);
    (zs_hash, ze_hash, t_hash, d_hash)
}

/// Allocate ring coefficients as witnesses and run the circuit.
/// Returns whether the constraint system is satisfied.
fn run_ring_verifier(
    challenge: Fr,
    zs: &[Fr],
    ze: &[Fr],
    t: &[Fr],
    d: &[Fr],
    hashes: (Fr, Fr, Fr, Fr),
) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let ext = RingEqExternalInputs5(hashes.0, hashes.1, hashes.2, hashes.3, challenge);
    let ext_var = RingEqExternalInputs5Var::new_witness(cs.clone(), || Ok(ext)).unwrap();

    let mut ring_coeffs = Vec::with_capacity(1024);
    ring_coeffs.extend_from_slice(zs);
    ring_coeffs.extend_from_slice(ze);
    ring_coeffs.extend_from_slice(t);
    ring_coeffs.extend_from_slice(d);

    let circuit = RingVerifierCircuit::new((challenge, ring_coeffs)).unwrap();
    let z_i = vec![FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::zero())).unwrap()];
    let _next = circuit
        .generate_step_constraints(cs.clone(), 0, z_i, ext_var)
        .unwrap();
    cs.is_satisfied().unwrap()
}

// ── Test 1: Honest ring equation (c=1) passes ─────────────────────────────

#[test]
fn g1_honest_c1_passes() {
    let challenge = Fr::one();
    let (zs, ze, t, d) = honest_ring_coeffs_c1();
    let hashes = compute_hashes(&zs, &ze, &t, &d);
    assert!(
        run_ring_verifier(challenge, &zs, &ze, &t, &d, hashes),
        "G1: honest ring equation with c=1 must satisfy constraints"
    );
}

// ── Test 2: Honest ring equation (c=-1) passes ────────────────────────────

#[test]
fn g1_honest_cm1_passes() {
    let challenge = -Fr::one();
    let (zs, ze, t, d) = honest_ring_coeffs_cm1();
    let hashes = compute_hashes(&zs, &ze, &t, &d);
    assert!(
        run_ring_verifier(challenge, &zs, &ze, &t, &d, hashes),
        "G1: honest ring equation with c=-1 must satisfy constraints"
    );
}

// ── Test 3: Honest ring equation (c=0) passes ────────────────────────────

#[test]
fn g1_honest_c0_passes() {
    let challenge = Fr::zero();
    let (zs, ze, t, d) = honest_ring_coeffs_c0();
    let hashes = compute_hashes(&zs, &ze, &t, &d);
    assert!(
        run_ring_verifier(challenge, &zs, &ze, &t, &d, hashes),
        "G1: honest ring equation with c=0 must satisfy constraints"
    );
}

// ── Test 4: Tampered z_s fails ───────────────────────────────────────────

#[test]
fn g1_wrong_zs_fails() {
    let challenge = Fr::one();
    let (mut zs, ze, t, d) = honest_ring_coeffs_c1();
    let hashes = compute_hashes(&zs, &ze, &t, &d);
    // Tamper z_s: change one coefficient without updating the hash
    zs[0] = Fr::from(999999u64);
    assert!(
        !run_ring_verifier(challenge, &zs, &ze, &t, &d, hashes),
        "G1: tampered z_s with stale hash must fail constraint check"
    );
}

// ── Test 5: Wrong challenge value fails ──────────────────────────────────

#[test]
fn g1_wrong_challenge_fails() {
    // Use c=1 equation (z_s + z_e = t + d) but set challenge to -1
    let challenge = -Fr::one();
    let (zs, ze, t, d) = honest_ring_coeffs_c1();
    let hashes = compute_hashes(&zs, &ze, &t, &d);
    assert!(
        !run_ring_verifier(challenge, &zs, &ze, &t, &d, hashes),
        "G1: c=1 coefficients with challenge=-1 must fail"
    );
}

// ── Test 6: Hash mismatch detected ───────────────────────────────────────

#[test]
fn g1_tampered_hash_fails() {
    let challenge = Fr::one();
    let (zs, ze, t, d) = honest_ring_coeffs_c1();
    let mut hashes = compute_hashes(&zs, &ze, &t, &d);
    // Tamper the z_s hash: replace with a wrong value
    hashes.0 = Fr::from(0xDEADu64);
    assert!(
        !run_ring_verifier(challenge, &zs, &ze, &t, &d, hashes),
        "G1: wrong z_s hash must fail constraint check"
    );
}

// ── Test 7: Mixed tampered t fails (c=0 case) ────────────────────────────

#[test]
fn g1_wrong_t_c0_fails() {
    let challenge = Fr::zero();
    let (zs, ze, mut t, d) = honest_ring_coeffs_c0();
    let hashes = compute_hashes(&zs, &ze, &t, &d);
    // Tamper t without updating hash: ze[0] == 5, set t[0] = 99
    t[0] = Fr::from(99u64);
    assert!(
        !run_ring_verifier(challenge, &zs, &ze, &t, &d, hashes),
        "G1: tampered t with c=0 must fail"
    );
}
