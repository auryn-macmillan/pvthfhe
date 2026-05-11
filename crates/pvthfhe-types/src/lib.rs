//! Shared byte-classification newtypes for PVTHFHE protocol boundaries.
//!
//! [`WitnessLeakingProofBytesV0`] is a quarantine wrapper for prototype proof
//! envelopes that still carry witness material. It is intentionally loud and
//! must be replaced by the R3 NIZK construction rather than normalized as public
//! protocol data.

pub mod witness_language;

use serde::{Deserialize, Serialize};
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

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

/// Quarantine wrapper for prototype proof bytes that leak witness material.
///
/// WARNING: this is not public protocol data. The V0 PVSS share proof envelope
/// serializes witness material by design in the research prototype. R3 must
/// replace this type with a real zero-knowledge proof payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WitnessLeakingProofBytesV0(pub Vec<u8>);

impl WitnessLeakingProofBytesV0 {
    /// Borrow the leaking prototype proof bytes.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Return the length of the leaking prototype proof bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the leaking prototype proof bytes are empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for WitnessLeakingProofBytesV0 {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Deref for WitnessLeakingProofBytesV0 {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl DerefMut for WitnessLeakingProofBytesV0 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut_slice()
    }
}
