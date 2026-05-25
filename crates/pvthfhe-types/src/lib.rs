//! Shared byte-classification newtypes for PVTHFHE protocol boundaries.

pub mod witness_language;

use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// BFV parameter preset for runtime parameter selection.
#[derive(Clone, Debug)]
pub struct BfvParameterPreset {
    /// Polynomial ring degree N (power of two).
    pub n: usize,
    /// RNS moduli q_0, q_1, ... (each q_i ≡ 1 mod 2N for NTT).
    pub moduli: Vec<u64>,
    /// Plaintext modulus t (coefficient space Z_t).
    pub plaintext_modulus: u64,
    /// Gaussian error bound (∞-norm).
    pub gaussian_bound: u64,
}

impl BfvParameterPreset {
    /// Insecure preset for fast iteration (N=512, 1 limb ~40 bits).
    pub fn insecure512() -> Self {
        Self {
            n: 512,
            moduli: vec![549755903489],
            plaintext_modulus: 100,
            gaussian_bound: 16,
        }
    }

    /// Production preset (N=8192, 3 RNS limbs, ~174 bits total modulus).
    pub fn production8192() -> Self {
        Self {
            n: 8192,
            moduli: vec![
                288_230_376_173_076_481,
                288_230_376_167_047_169,
                288_230_376_161_280_001,
            ],
            plaintext_modulus: 65536,
            gaussian_bound: 16,
        }
    }
}

static ACTIVE_PRESET: OnceLock<BfvParameterPreset> = OnceLock::new();

/// Set the globally active BFV parameter preset.
///
/// Must be called before any NIZK/FHE operations. Subsequent calls are
/// silently ignored (first-write-wins via `OnceLock`).
pub fn set_active_preset(preset: BfvParameterPreset) {
    let _ = ACTIVE_PRESET.set(preset);
}

/// Return the active RLWE ring degree N.
pub fn rlwe_n() -> usize {
    ACTIVE_PRESET.get().map(|p| p.n).unwrap_or(8192)
}

/// Return the active RNS moduli.
pub fn rlwe_moduli() -> Vec<u64> {
    ACTIVE_PRESET
        .get()
        .map(|p| p.moduli.clone())
        .unwrap_or_else(|| {
            vec![
                288_230_376_173_076_481,
                288_230_376_167_047_169,
                288_230_376_161_280_001,
            ]
        })
}

/// Return the active plaintext modulus.
pub fn rlwe_plaintext_modulus() -> u64 {
    ACTIVE_PRESET
        .get()
        .map(|p| p.plaintext_modulus)
        .unwrap_or(65536)
}

/// Return the active Gaussian bound.
pub fn rlwe_gaussian_bound() -> u64 {
    ACTIVE_PRESET.get().map(|p| p.gaussian_bound).unwrap_or(16)
}

/// Secret material that is zeroized on drop.
///
/// This wrapper intentionally does not implement `Debug`, `Serialize`, or
/// `Deserialize`; callers must make any wire conversion explicit at the boundary.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Secret<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> Secret<T> {
    /// Wrap secret material.
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Borrow the wrapped secret material.
    pub fn expose_secret(&self) -> &T {
        &self.inner
    }

    /// Consume the wrapper and return the inner value.
    pub fn into_inner(self) -> T {
        let this = ManuallyDrop::new(self);
        // SAFETY: `this` will not be dropped, and ownership of `inner` is
        // transferred to the caller. The caller is then responsible for the
        // returned secret material's lifetime and eventual zeroization.
        unsafe { core::ptr::read(&this.inner) }
    }
}

impl<T: Zeroize> core::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Shamir/PVSS share bytes.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct ShareSecret {
    inner: Secret<Vec<u8>>,
}

impl ShareSecret {
    /// Wrap share bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: Secret::new(bytes),
        }
    }

    /// Borrow share bytes.
    pub fn expose(&self) -> &[u8] {
        self.inner.expose_secret().as_slice()
    }

    /// Copy share bytes for explicit prototype wire envelopes.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.expose().to_vec()
    }

    /// Reconstruct share bytes from an explicit prototype wire envelope.
    pub fn from_wire_bytes(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }
}

impl core::fmt::Debug for ShareSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShareSecret")
            .field("len", &self.expose().len())
            .finish()
    }
}

/// Placeholder wrapper for FHE secret-key material.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct Sk<T: Zeroize> {
    inner: Secret<T>,
}

impl<T: Zeroize> Sk<T> {
    /// Wrap secret-key material.
    pub fn new(inner: T) -> Self {
        Self {
            inner: Secret::new(inner),
        }
    }

    /// Borrow secret-key material.
    pub fn expose(&self) -> &T {
        self.inner.expose_secret()
    }
}

impl<T: Zeroize> core::fmt::Debug for Sk<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Sk(<redacted>)")
    }
}

/// Placeholder wrapper for RLWE noise polynomial material.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct NoisePoly {
    inner: Secret<Vec<u8>>,
}

impl NoisePoly {
    /// Wrap serialized noise polynomial bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: Secret::new(bytes),
        }
    }

    /// Borrow serialized noise polynomial bytes.
    pub fn expose(&self) -> &[u8] {
        self.inner.expose_secret().as_slice()
    }
}

impl core::fmt::Debug for NoisePoly {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NoisePoly")
            .field("len", &self.expose().len())
            .finish()
    }
}

/// Encryption randomness witness bytes.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct EncRandomness {
    inner: Secret<Vec<u8>>,
}

impl EncRandomness {
    /// Wrap encryption randomness bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: Secret::new(bytes),
        }
    }

    /// Borrow encryption randomness bytes.
    pub fn expose(&self) -> &[u8] {
        self.inner.expose_secret().as_slice()
    }

    /// Copy randomness bytes for explicit prototype wire envelopes.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.expose().to_vec()
    }

    /// Reconstruct randomness bytes from an explicit prototype wire envelope.
    pub fn from_wire_bytes(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }
}

impl core::fmt::Debug for EncRandomness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncRandomness")
            .field("len", &self.expose().len())
            .finish()
    }
}

/// CCS witness bytes produced by the P1 layer.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct CcsWitnessSecret {
    inner: Secret<Vec<u8>>,
}

impl CcsWitnessSecret {
    /// Wrap serialized CCS witness bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: Secret::new(bytes),
        }
    }

    /// Borrow serialized CCS witness bytes.
    pub fn expose(&self) -> &[u8] {
        self.inner.expose_secret().as_slice()
    }

    /// Copy witness bytes for explicit prototype wire envelopes.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.expose().to_vec()
    }

    /// Reconstruct witness bytes from an explicit prototype wire envelope.
    pub fn from_wire_bytes(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }
}

impl core::fmt::Debug for CcsWitnessSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CcsWitnessSecret")
            .field("len", &self.expose().len())
            .finish()
    }
}

/// Public protocol bytes with transparent serde encoding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProtocolBytes(pub Vec<u8>);

impl ProtocolBytes {
    /// Borrow the wrapped protocol bytes.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns true if the wrapped protocol bytes are empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Return the length of the wrapped protocol bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<Vec<u8>> for ProtocolBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Deref for ProtocolBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl DerefMut for ProtocolBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut_slice()
    }
}

/// BFV encryption witness material for proof generation.
///
/// Contains the full set of polynomials needed to construct a well-formedness
/// proof for a BFV ciphertext: the plaintext polynomial `m`, encryption
/// randomness `u`, error polynomials `e0` (ct₀ leg) and `e1` (ct₁ leg),
/// ciphertext components, and the canonical ciphertext serialization.
///
/// This type intentionally does not implement `Debug`, `Serialize`, or
/// `Deserialize`; callers must make any wire conversion explicit at the boundary.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EncryptionWitness {
    /// Message as polynomial coefficient bytes (plaintext poly m in NTT).
    pub plaintext_poly_bytes: Vec<u8>,
    /// Encryption randomness polynomial u (CBD with SK_VARIANCE).
    pub u_poly_bytes: Vec<u8>,
    /// Error polynomial for the ct₀ leg (e₁ in fhe.rs nomenclature).
    pub e0_poly_bytes: Vec<u8>,
    /// Error polynomial for the ct₁ leg (e₂ in fhe.rs nomenclature).
    pub e1_poly_bytes: Vec<u8>,
    /// Ciphertext component 0 polynomial bytes.
    pub ct0_poly_bytes: Vec<u8>,
    /// Ciphertext component 1 polynomial bytes.
    pub ct1_poly_bytes: Vec<u8>,
    /// Canonical ciphertext serialization (prost-encoded BfvCiphertext).
    pub ciphertext_bytes: Vec<u8>,
    /// Recipient public-key component pk0 polynomial bytes (power-basis).
    pub recipient_pk0_bytes: Vec<u8>,
    /// Recipient public-key component pk1 polynomial bytes (power-basis).
    pub recipient_pk1_bytes: Vec<u8>,
}

impl EncryptionWitness {
    /// Returns true if any witness field is empty (useful for sanity checks).
    pub fn is_complete(&self) -> bool {
        !self.plaintext_poly_bytes.is_empty()
            && !self.u_poly_bytes.is_empty()
            && !self.e0_poly_bytes.is_empty()
            && !self.e1_poly_bytes.is_empty()
            && !self.ct0_poly_bytes.is_empty()
            && !self.ct1_poly_bytes.is_empty()
            && !self.ciphertext_bytes.is_empty()
            && !self.recipient_pk0_bytes.is_empty()
            && !self.recipient_pk1_bytes.is_empty()
    }
}

impl core::fmt::Debug for EncryptionWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let complete = self.is_complete();
        f.debug_struct("EncryptionWitness")
            .field("complete", &complete)
            .field("ciphertext_len", &self.ciphertext_bytes.len())
            .finish()
    }
}

/// Threshold-decryption witness material produced alongside a [`DecryptShare`].
///
/// Contains the polynomial decompositions needed by the proof layer:
/// ciphertext components, aggregated secret-key share, smudging noise,
/// pre- and post-smudge decryption shares, and quotient/reduction terms.
///
/// # Security
///
/// This type zeroizes on drop and its [`Debug`] implementation redacts
/// all secret material.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct DecryptionWitness {
    /// Ciphertext component 0 polynomial bytes (ct₀).
    pub ct0_poly_bytes: Vec<u8>,
    /// Ciphertext component 1 polynomial bytes (ct₁).
    pub ct1_poly_bytes: Vec<u8>,
    /// Aggregated secret-key share polynomial bytes.
    pub sk_agg_poly_bytes: Vec<u8>,
    /// Smudging-noise polynomial bytes (fresh local or committed e_sm).
    pub esm_noise_poly_bytes: Vec<u8>,
    /// Quotient/reduction polynomial bytes per limb.
    /// Empty when not directly accessible from the backend.
    pub quotient_poly_bytes: Vec<Vec<u8>>,
    /// Resulting decryption-share polynomial bytes (post-smudge).
    pub d_share_poly_bytes: Vec<u8>,
    /// Canonical decryption share serialization (wire-encoded).
    pub decrypted_share_bytes: Vec<u8>,
    /// `true` when using committed e_sm; `false` for fresh local smudging.
    pub esm_committed: bool,
}

impl core::fmt::Debug for DecryptionWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let ct0_nonempty = !self.ct0_poly_bytes.is_empty();
        let ct1_nonempty = !self.ct1_poly_bytes.is_empty();
        let sk_nonempty = !self.sk_agg_poly_bytes.is_empty();
        f.debug_struct("DecryptionWitness")
            .field("ct0_filled", &ct0_nonempty)
            .field("ct1_filled", &ct1_nonempty)
            .field("sk_agg_filled", &sk_nonempty)
            .field("esm_committed", &self.esm_committed)
            .finish()
    }
}
