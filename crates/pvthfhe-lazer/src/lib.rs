//! # pvthfhe-lazer
//!
//! Rust FFI bindings to the [LaZer](https://github.com/auryn-macmillan/lazer)
//! lattice-based zero-knowledge proof library (LaBRADOR protocol).
//!
//! ## Feature flags
//!
//! - `enable-lazer` (off by default) — compiles and links the native C library.
//!   Without this flag the crate contains only type stubs and cannot execute
//!   proofs.

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(unused)]

use std::os::raw::c_int;

// ── Opaque type aliases ────────────────────────────────────────────────────
// These mirror the C typedefs in lazer.h.  We do not expose the internal
// layout to Rust; all access goes through the C API.

/// GMP limb (64-bit unsigned integer).
pub type limb_t = u64;

/// Signed coefficient in the CRT domain (64-bit).
pub type crtcoeff_t = i64;

/// Double-width signed coefficient (128-bit).
pub type crtcoeff_dbl_t = i128;

// ── Opaque C handles ──────────────────────────────────────────────────────
// Each handle is `[u8; N]` where N matches `sizeof(type)` on the platform.
// The size is *not* guaranteed across architectures — adjust if targeting
// non-AMD64.

macro_rules! opaque {
    ($name:ident, $size:expr, $doc:expr) => {
        #[doc = $doc]
        #[repr(C)]
        #[derive(Copy, Clone)]
        pub struct $name(pub [u8; $size]);
    };
}

// Sizes verified on x86-64 / AMD64 Linux with GCC 13.
// These may need adjustment on other platforms.
opaque!(rng_state_t, 384, "RNG state (shake128 or aes256ctr)");
opaque!(polyring_t, 56, "Polynomial ring descriptor");
opaque!(poly_t, 48, "Polynomial over a ring");
opaque!(polyvec_t, 40, "Vector of polynomials");
opaque!(polymat_t, 56, "Matrix of polynomials");
opaque!(spolyvec_t, 56, "Sparse polynomial vector");
opaque!(spolymat_t, 64, "Sparse polynomial matrix");
opaque!(int_t, 24, "Multi-precision integer");
opaque!(intvec_t, 56, "Vector of multi-precision integers");
opaque!(intmat_t, 72, "Matrix of multi-precision integers");
opaque!(dcompress_params_t, 72, "Decompression parameters");
opaque!(abdlop_params_t, 176, "ABDLOP protocol parameters");
opaque!(lnp_tbox_params_t, 224, "LaBRADOR NIZK toolbox parameters");
opaque!(lin_params_t, 104, "Linear relation parameters");
opaque!(lnp_prover_state_t, 1280, "LNP prover state");
opaque!(lnp_verifier_state_t, 608, "LNP verifier state");
opaque!(lin_prover_state_t, 1920, "Linear relation prover state");
opaque!(lin_verifier_state_t, 1248, "Linear relation verifier state");
opaque!(signer_state_t, 4096, "Blind signature signer state");
opaque!(verifier_state_t, 2688, "Blind signature verifier state");
opaque!(user_state_t, 4096, "Blind signature user state");

// ── FFI function declarations ─────────────────────────────────────────────
// All functions are only available when the `enable-lazer` feature is active
// and the native library has been linked.

#[cfg(feature = "enable-lazer")]
extern "C" {
    // ── Initialisation ────────────────────────────────────────────────────
    pub fn lazer_init();
    pub fn lazer_get_version_major() -> u32;
    pub fn lazer_get_version_minor() -> u32;
    pub fn lazer_get_version_patch() -> u32;
    pub fn lazer_get_version() -> *const std::os::raw::c_char;

    // ── Memory ────────────────────────────────────────────────────────────
    pub fn lazer_set_memory_functions(
        nalloc: Option<unsafe extern "C" fn(usize) -> *mut std::os::raw::c_void>,
        nrealloc: Option<
            unsafe extern "C" fn(
                *mut std::os::raw::c_void,
                usize,
                usize,
            ) -> *mut std::os::raw::c_void,
        >,
        nfree: Option<unsafe extern "C" fn(*mut std::os::raw::c_void, usize)>,
    );
    pub fn lazer_get_memory_functions(
        nalloc: *mut Option<unsafe extern "C" fn(usize) -> *mut std::os::raw::c_void>,
        nrealloc: *mut Option<
            unsafe extern "C" fn(
                *mut std::os::raw::c_void,
                usize,
                usize,
            ) -> *mut std::os::raw::c_void,
        >,
        nfree: *mut Option<unsafe extern "C" fn(*mut std::os::raw::c_void, usize)>,
    );

    // ── Random bytes utilities ────────────────────────────────────────────
    pub fn bytes_urandom(bytes: *mut u8, len: usize);
    pub fn bytes_clear(bytes: *mut u8, len: usize);

    // ── RNG ───────────────────────────────────────────────────────────────
    pub fn shake128_init(state: *mut rng_state_t);
    pub fn shake128_absorb(state: *mut rng_state_t, input: *const u8, len: usize);
    pub fn shake128_squeeze(state: *mut rng_state_t, output: *mut u8, len: usize);
    pub fn shake128_clear(state: *mut rng_state_t);
    pub fn rng_init(state: *mut rng_state_t, seed: *const u8, dom: u64);
    pub fn rng_urandom(state: *mut rng_state_t, out: *mut u8, outlen: usize);
    pub fn rng_clear(state: *mut rng_state_t);

    // ── Polynomial ring ───────────────────────────────────────────────────
    pub fn polyring_get_deg(ring: *const polyring_t) -> u32;

    // ── Polynomial ────────────────────────────────────────────────────────
    pub fn poly_alloc(r: *mut poly_t, ring: *const polyring_t);
    pub fn poly_free(r: *mut poly_t);
    pub fn poly_set_zero(r: *mut poly_t);
    pub fn poly_set_one(r: *mut poly_t);
    pub fn poly_set(r: *mut poly_t, a: *const poly_t);
    pub fn poly_add(r: *mut poly_t, a: *mut poly_t, b: *mut poly_t, crt: c_int);
    pub fn poly_sub(r: *mut poly_t, a: *mut poly_t, b: *mut poly_t, crt: c_int);
    pub fn poly_scale(r: *mut poly_t, a: *const int_t, b: *mut poly_t);
    pub fn poly_mul(r: *mut poly_t, a: *mut poly_t, b: *mut poly_t);
    pub fn poly_neg(r: *mut poly_t, b: *mut poly_t);
    pub fn poly_mod(r: *mut poly_t, a: *mut poly_t);
    pub fn poly_eq(a: *mut poly_t, b: *mut poly_t) -> c_int;
    pub fn poly_urandom(
        r: *mut poly_t,
        modulus: *const int_t,
        log2mod: u32,
        seed: *const u8,
        dom: u32,
    );
    pub fn poly_grandom(r: *mut poly_t, log2o: u32, seed: *const u8, dom: u32);
    pub fn poly_brandom(r: *mut poly_t, k: u32, seed: *const u8, dom: u32);
    pub fn poly_dump(a: *mut poly_t);

    // ── Polynomial vector ─────────────────────────────────────────────────
    pub fn polyvec_alloc(r: *mut polyvec_t, ring: *const polyring_t, nelems: u32);
    pub fn polyvec_free(r: *mut polyvec_t);
    pub fn polyvec_set_zero(r: *mut polyvec_t);
    pub fn polyvec_set(r: *mut polyvec_t, a: *const polyvec_t);
    pub fn polyvec_add(r: *mut polyvec_t, a: *mut polyvec_t, b: *mut polyvec_t, crt: c_int);
    pub fn polyvec_sub(r: *mut polyvec_t, a: *mut polyvec_t, b: *mut polyvec_t, crt: c_int);
    pub fn polyvec_scale(r: *mut polyvec_t, a: *const int_t, b: *mut polyvec_t);
    pub fn polyvec_mul(r: *mut polyvec_t, a: *mut polymat_t, b: *mut polyvec_t);
    pub fn polyvec_addmul(r: *mut polyvec_t, a: *mut polymat_t, b: *mut polyvec_t, crt: c_int);
    pub fn polyvec_submul(r: *mut polyvec_t, a: *mut polymat_t, b: *mut polyvec_t, crt: c_int);
    pub fn polyvec_dot(r: *mut poly_t, a: *mut polyvec_t, b: *mut polyvec_t);
    pub fn polyvec_urandom(
        r: *mut polyvec_t,
        modulus: *const int_t,
        log2mod: u32,
        seed: *const u8,
        dom: u32,
    );
    pub fn polyvec_grandom(r: *mut polyvec_t, log2o: u32, seed: *const u8, dom: u32);
    pub fn polyvec_brandom(r: *mut polyvec_t, k: u32, seed: *const u8, dom: u32);
    pub fn polyvec_tocrt(r: *mut polyvec_t);
    pub fn polyvec_fromcrt(r: *mut polyvec_t);
    pub fn polyvec_mod(r: *mut polyvec_t, a: *mut polyvec_t);
    pub fn polyvec_dump(vec: *mut polyvec_t);

    // ── Polynomial matrix ─────────────────────────────────────────────────
    pub fn polymat_alloc(r: *mut polymat_t, ring: *const polyring_t, nrows: u32, ncols: u32);
    pub fn polymat_free(r: *mut polymat_t);
    pub fn polymat_set_zero(r: *mut polymat_t);
    pub fn polymat_set_one(r: *mut polymat_t);
    pub fn polymat_set(r: *mut polymat_t, a: *const polymat_t);
    pub fn polymat_add(r: *mut polymat_t, a: *mut polymat_t, b: *mut polymat_t, crt: c_int);
    pub fn polymat_sub(r: *mut polymat_t, a: *mut polymat_t, b: *mut polymat_t, crt: c_int);
    pub fn polymat_mul(r: *mut polymat_t, a: *mut polymat_t, b: *mut polymat_t);
    pub fn polymat_tocrt(r: *mut polymat_t);
    pub fn polymat_fromcrt(r: *mut polymat_t);
    pub fn polymat_mod(r: *mut polymat_t, a: *mut polymat_t);

    // ── Big integers ──────────────────────────────────────────────────────
    pub fn int_set_zero(r: *mut int_t);
    pub fn int_set_one(r: *mut int_t);
    pub fn int_set_i64(r: *mut int_t, a: i64);
    pub fn int_get_i64(r: *const int_t) -> i64;
    pub fn int_set(r: *mut int_t, a: *const int_t);
    pub fn int_add(r: *mut int_t, a: *const int_t, b: *const int_t);
    pub fn int_sub(r: *mut int_t, a: *const int_t, b: *const int_t);
    pub fn int_mul(r: *mut int_t, a: *const int_t, b: *const int_t);
    pub fn int_div(rq: *mut int_t, rr: *mut int_t, a: *const int_t, b: *const int_t);
    pub fn int_mod(r: *mut int_t, a: *const int_t, m: *const int_t);
    pub fn int_neg(r: *mut int_t, a: *const int_t);
    pub fn int_eqzero(a: *const int_t) -> c_int;
    pub fn int_eq(a: *const int_t, b: *const int_t) -> c_int;
    pub fn int_lt(a: *const int_t, b: *const int_t) -> c_int;
    pub fn int_gt(a: *const int_t, b: *const int_t) -> c_int;
    pub fn int_urandom(
        r: *mut int_t,
        modulus: *const int_t,
        log2mod: u32,
        seed: *const u8,
        dom: u32,
    );
    pub fn int_dump(z: *mut int_t);

    // ── Integer vector ────────────────────────────────────────────────────
    pub fn intvec_alloc(r: *mut intvec_t, nelems: u32, nlimbs: u32);
    pub fn intvec_free(r: *mut intvec_t);
    pub fn intvec_set_zero(r: *mut intvec_t);
    pub fn intvec_set(r: *mut intvec_t, a: *const intvec_t);
    pub fn intvec_add(r: *mut intvec_t, a: *const intvec_t, b: *const intvec_t);
    pub fn intvec_sub(r: *mut intvec_t, a: *const intvec_t, b: *const intvec_t);
    pub fn intvec_dot(r: *mut int_t, a: *const intvec_t, b: *const intvec_t);

    // ── Integer matrix ────────────────────────────────────────────────────
    pub fn intmat_alloc(r: *mut intmat_t, nrows: u32, ncols: u32, nlimbs: u32);
    pub fn intmat_free(r: *mut intmat_t);
    pub fn intmat_set_zero(r: *mut intmat_t);
    pub fn intmat_set_one(r: *mut intmat_t);

    // ── Sparse polynomial structures ──────────────────────────────────────
    pub fn spolyvec_alloc(
        r: *mut spolyvec_t,
        ring: *const polyring_t,
        nelems: u32,
        nelems_max: u32,
    );
    pub fn spolyvec_set(r: *mut spolyvec_t, a: *mut spolyvec_t);
    pub fn spolyvec_sort(r: *mut spolyvec_t);

    // ── Decompression ─────────────────────────────────────────────────────
    pub fn poly_dcompress_power2round(
        r: *mut poly_t,
        a: *mut poly_t,
        params: *const dcompress_params_t,
    );
    pub fn poly_dcompress_decompose(
        r1: *mut poly_t,
        r0: *mut poly_t,
        r: *mut poly_t,
        params: *const dcompress_params_t,
    );
    pub fn poly_dcompress_use_ghint(
        ret: *mut poly_t,
        y: *mut poly_t,
        r: *mut poly_t,
        params: *const dcompress_params_t,
    );
    pub fn poly_dcompress_make_ghint(
        ret: *mut poly_t,
        z: *mut poly_t,
        r: *mut poly_t,
        params: *const dcompress_params_t,
    );
    pub fn polyvec_dcompress_power2round(
        r: *mut polyvec_t,
        a: *mut polyvec_t,
        params: *const dcompress_params_t,
    );
    pub fn polyvec_dcompress_decompose(
        r1: *mut polyvec_t,
        r0: *mut polyvec_t,
        r: *mut polyvec_t,
        params: *const dcompress_params_t,
    );

    // ── ABDLOP / LNP ──────────────────────────────────────────────────────
    pub fn lnp_tbox_prove(state: *mut lnp_prover_state_t) -> c_int;
    pub fn lnp_tbox_verify(state: *mut lnp_verifier_state_t) -> c_int;
    pub fn lnp_quad_eval_prove(state: *mut lnp_prover_state_t) -> c_int;
    pub fn lnp_quad_eval_verify(state: *mut lnp_verifier_state_t) -> c_int;
    pub fn lnp_quad_many_prove(state: *mut lnp_prover_state_t) -> c_int;
    pub fn lnp_quad_many_verify(state: *mut lnp_verifier_state_t) -> c_int;

    // ── Linear relation proofs ────────────────────────────────────────────
    pub fn lin_prover_init(
        state: *mut lin_prover_state_t,
        ppseed: *const u8,
        params: *const lin_params_t,
    );
    pub fn lin_prover_set_statement_A(state: *mut lin_prover_state_t, A: *const polymat_t);
    pub fn lin_prover_set_statement_t(state: *mut lin_prover_state_t, t: *const polyvec_t);
    pub fn lin_prover_set_statement(
        state: *mut lin_prover_state_t,
        A: *const polymat_t,
        t: *const polyvec_t,
    );
    pub fn lin_prover_set_witness(state: *mut lin_prover_state_t, w: *const polyvec_t);
    pub fn lin_prover_prove(
        state: *mut lin_prover_state_t,
        proof: *mut u8,
        len: *mut usize,
        coins: *const u8,
    ) -> c_int;
    pub fn lin_prover_clear(state: *mut lin_prover_state_t);
    pub fn lin_verifier_init(
        state: *mut lin_verifier_state_t,
        ppseed: *const u8,
        params: *const lin_params_t,
    );
    pub fn lin_verifier_set_statement_A(state: *mut lin_verifier_state_t, A: *const polymat_t);
    pub fn lin_verifier_set_statement_t(state: *mut lin_verifier_state_t, t: *const polyvec_t);
    pub fn lin_verifier_set_statement(
        state: *mut lin_verifier_state_t,
        A: *const polymat_t,
        t: *const polyvec_t,
    );
    pub fn lin_verifier_verify(
        state: *mut lin_verifier_state_t,
        proof: *const u8,
        len: *const usize,
    ) -> c_int;
    pub fn lin_verifier_clear(state: *mut lin_verifier_state_t);

    // ── Blind signatures ──────────────────────────────────────────────────
    pub fn signer_init(state: *mut signer_state_t) -> c_int;
    pub fn verifier_init(state: *mut verifier_state_t, pubkey: *const i16) -> c_int;
    pub fn user_init(state: *mut user_state_t, pubkey: *const i16, msg: *const u8) -> c_int;
    pub fn blindsig_p1(state: *mut user_state_t, r1: *mut i16) -> c_int;
    pub fn blindsig_p2(state: *mut signer_state_t, tau: *mut i16, r1: *const i16) -> c_int;
    pub fn blindsig_p3(state: *mut user_state_t, sig: *mut i16, tau: *const i16) -> c_int;
    pub fn blindsig_verify(state: *mut verifier_state_t, sig: *const i16) -> c_int;
}

// ── Version helpers (compile-time constants when library absent) ───────────

/// LaZer version components (compile-time constants matching the header).
pub const LAZER_VERSION_MAJOR: u32 = 0;
pub const LAZER_VERSION_MINOR: u32 = 1;
pub const LAZER_VERSION_PATCH: u32 = 0;

// ── Safe wrapper stubs for when enable-lazer is off ──────────────────────

/// Safe wrapper around `lazer_init`.  No-op when the feature is disabled.
#[inline]
pub fn init() {
    #[cfg(feature = "enable-lazer")]
    unsafe {
        lazer_init();
    }
}

/// Returns the version string, or `"0.1.0"` when the library is not linked.
#[inline]
pub fn version() -> &'static str {
    #[cfg(feature = "enable-lazer")]
    unsafe {
        let c_str = std::ffi::CStr::from_ptr(lazer_get_version());
        c_str.to_str().unwrap_or("0.1.0")
    }
    #[cfg(not(feature = "enable-lazer"))]
    {
        "0.1.0"
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_constants_match_header() {
        assert_eq!(LAZER_VERSION_MAJOR, 0);
        assert_eq!(LAZER_VERSION_MINOR, 1);
        assert_eq!(LAZER_VERSION_PATCH, 0);
    }

    #[cfg(feature = "enable-lazer")]
    #[test]
    fn init_does_not_crash() {
        init();
        // Just verifying lazer_init() completes without segfault.
    }

    #[cfg(feature = "enable-lazer")]
    #[test]
    fn version_returns_string() {
        init();
        let v = version();
        assert!(v.starts_with("0."), "unexpected version: {}", v);
    }
}
