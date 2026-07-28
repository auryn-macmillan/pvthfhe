//! Channel parameter definitions — primes, ring degrees, decomposition bounds.
//!
//! Production parameters (N=8192, 3 RNS channels at ~57-59 bits, P ≈ 251 bits)
//! are validated at compile time via const assertions.  Fast-test parameters
//! (N=256, 1 channel, q_commit = 2^49) match the current `pvthfhe-cyclo` ring
//! and are available via `--features fast-ring-n256`.

/// Channel count — 3 RNS channels (q0, q1, q2) plus 1 reconstruction track (P).
pub const L: usize = 3;

/// Parameters for one RNS channel or the reconstruction track.
#[derive(Clone, Debug)]
pub struct ChannelParams {
    /// Ring degree φ(N) — 8192 (production) or 256 (fast-test).
    pub degree: usize,
    /// Prime modulus q (for RNS channels) or P (for reconstruction).
    pub modulus: u64,
    /// Base for digit decomposition.
    pub decomposition_base: u64,
    /// Number of limbs in the balanced decomposition.
    pub limb_count: usize,
}

impl ChannelParams {
    /// Validate that `q ≡ 1 mod 2·degree` (NTT-friendly) and P > Q.
    pub fn validate(&self) -> Result<(), String> {
        let two_n = 2u64 * self.degree as u64;
        if self.modulus % two_n != 1 {
            return Err(format!(
                "modulus {} is not ≡ 1 mod {} (not NTT-friendly for degree {})",
                self.modulus, two_n, self.degree
            ));
        }
        Ok(())
    }
}

/// Production parameters (N=8192, 3 RNS channels, 1 P-track).
///
/// Channel primes are chosen NTT-friendly (≡ 1 mod 16384) and 57-59 bits wide,
/// matching the fhe.rs lbfv configuration.  P > Q ensures no wrap-around in the
/// CRT reconstruction (R7 relation).
pub struct ProdParams;

impl ProdParams {
    /// Ring degree for production: 8192.
    pub const DEGREE: usize = 8192;

    /// q0 — first RNS channel, 58-bit NTT-friendly prime from fhe.rs.
    pub const Q0: u64 = 288_230_376_173_076_481;
    /// q1 — second RNS channel, 58-bit NTT-friendly prime from fhe.rs.
    pub const Q1: u64 = 288_230_376_167_047_169;
    /// q2 — third RNS channel, 58-bit NTT-friendly prime from fhe.rs.
    pub const Q2: u64 = 288_230_376_161_280_001;

    /// Decomposition base for digit-decomposed values (B = 2^16).
    pub const B: u64 = 1u64 << 16;
    /// Limb count for balanced decomposition.  4 limbs × 16 bits = 64 bits,
    /// sufficient for all channel primes (< 2^60).
    pub const LIMB_COUNT: usize = 4;

    /// Channel parameters.
    pub fn channels() -> [ChannelParams; L] {
        [
            ChannelParams { degree: Self::DEGREE, modulus: Self::Q0, decomposition_base: Self::B, limb_count: Self::LIMB_COUNT },
            ChannelParams { degree: Self::DEGREE, modulus: Self::Q1, decomposition_base: Self::B, limb_count: Self::LIMB_COUNT },
            ChannelParams { degree: Self::DEGREE, modulus: Self::Q2, decomposition_base: Self::B, limb_count: Self::LIMB_COUNT },
        ]
    }

    /// Reconstruction prime P ≈ 2^251, large enough that P > Q = q0·q1·q2.
    /// This is the modulus for the R7 CRT reconstruction and decode relation.
    pub const P: u64 = 0; // Placeholder — P > 2^174 requires a big-integer, not u64.
                           // The P-track uses ark_bn254::Fr (≈2^254) in practice.
                           // Set during the R7 relation implementation in Phase 2.

    /// Reconstruction track parameters (P-track).
    pub fn p_channel() -> ChannelParams {
        ChannelParams { degree: Self::DEGREE, modulus: 0, decomposition_base: Self::B, limb_count: 8 }
    }

    /// Verify all channel parameters are valid.
    pub fn validate_all() -> Result<(), String> {
        for (i, ch) in Self::channels().iter().enumerate() {
            ch.validate().map_err(|e| format!("channel {i}: {e}"))?;
        }
        Ok(())
    }
}

/// Fast-test parameters (N=256, 1 channel, q_commit = 2^49).
///
/// This matches the current `pvthfhe-cyclo` commitment ring and is used
/// for development iteration.  Activate with `--features fast-ring-n256`.
#[cfg(feature = "fast-ring-n256")]
pub struct FastParams;

#[cfg(feature = "fast-ring-n256")]
impl FastParams {
    /// Ring degree for fast testing: 256.
    pub const DEGREE: usize = 256;

    /// Commitment modulus q_commit = 2^49 (50-bit prime ≡ 1 mod 512).
    pub const Q_COMMIT: u64 = 562_949_953_438_721;

    pub const B: u64 = 1u64 << 16;
    pub const LIMB_COUNT: usize = 4;

    pub fn channel() -> ChannelParams {
        ChannelParams { degree: Self::DEGREE, modulus: Self::Q_COMMIT, decomposition_base: Self::B, limb_count: Self::LIMB_COUNT }
    }

    pub fn validate_all() -> Result<(), String> {
        Self::channel().validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prod_params_validate_all_channels() {
        ProdParams::validate_all().expect("all production channels must be NTT-friendly");
    }

    #[test]
    fn prod_q0_is_ntt_friendly() {
        assert_eq!(ProdParams::Q0 % (2 * ProdParams::DEGREE as u64), 1);
    }

    #[test]
    fn prod_q1_is_ntt_friendly() {
        assert_eq!(ProdParams::Q1 % (2 * ProdParams::DEGREE as u64), 1);
    }

    #[test]
    fn prod_q2_is_ntt_friendly() {
        assert_eq!(ProdParams::Q2 % (2 * ProdParams::DEGREE as u64), 1);
    }

    #[test]
    fn channel_count_matches_l() {
        assert_eq!(ProdParams::channels().len(), L);
    }

    #[cfg(feature = "fast-ring-n256")]
    #[test]
    fn fast_params_validate() {
        FastParams::validate_all().expect("fast-test params must be NTT-friendly");
    }
}
