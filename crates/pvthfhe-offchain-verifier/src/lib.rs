//! # ⚠️ INTENTIONALLY MINIMAL

pub mod attestation;

/// Error returned when the compressor SRS hash does not match the on-chain registry value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrsMismatch {
    pub expected: [u8; 32],
    pub actual: [u8; 32],
}

impl std::fmt::Display for SrsMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SRS hash mismatch: expected 0x{}.., got 0x{}..",
            hex::encode(&self.expected[..4]),
            hex::encode(&self.actual[..4])
        )
    }
}

impl std::error::Error for SrsMismatch {}

/// Verify that a compressor's SRS hash matches the expected on-chain registry value.
pub fn check_srs_hash(
    compressor_srs_hash: &[u8; 32],
    onchain_srs_hash: &[u8; 32],
) -> Result<(), SrsMismatch> {
    if compressor_srs_hash == onchain_srs_hash {
        Ok(())
    } else {
        Err(SrsMismatch {
            expected: *onchain_srs_hash,
            actual: *compressor_srs_hash,
        })
    }
}
