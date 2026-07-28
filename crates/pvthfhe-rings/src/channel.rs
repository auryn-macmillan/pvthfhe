//! Concrete per-channel ring types and the multi-channel fold context.

use crate::params::{ChannelParams, ProdParams, L};
use crate::ring::FheMathRing;

/// All RNS channel rings, initialized and ready for per-channel folding.
pub struct RnsChannels {
    channels: Vec<FheMathRing>,
}

impl RnsChannels {
    /// Initialize channels from production parameters.
    pub fn production() -> Result<Self, String> {
        ProdParams::validate_all()?;
        let prod_channels = ProdParams::channels();
        let mut channels = Vec::with_capacity(L);
        for ch in &prod_channels {
            channels.push(FheMathRing::new(ch.clone())?);
        }
        Ok(Self { channels })
    }

    /// Initialize channels from custom parameters.
    pub fn from_params(params: &[ChannelParams]) -> Result<Self, String> {
        let mut channels = Vec::with_capacity(params.len());
        for ch in params {
            channels.push(FheMathRing::new(ch.clone())?);
        }
        Ok(Self { channels })
    }

    /// Number of channels.
    pub fn count(&self) -> usize { self.channels.len() }

    /// Get channel ring by index.
    pub fn get(&self, idx: usize) -> &FheMathRing {
        &self.channels[idx]
    }

    /// Iterate over all channel rings.
    pub fn iter(&self) -> impl Iterator<Item = &FheMathRing> {
        self.channels.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_channels_init() {
        let ch = RnsChannels::production().expect("production channels should initialize");
        assert_eq!(ch.count(), L);
        assert_eq!(ch.get(0).modulus(), ProdParams::Q0);
        assert_eq!(ch.get(1).modulus(), ProdParams::Q1);
        assert_eq!(ch.get(2).modulus(), ProdParams::Q2);
    }
}
