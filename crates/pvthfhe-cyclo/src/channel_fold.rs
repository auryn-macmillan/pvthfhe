//! Per-channel LatticeFold+ folding driver.
//!
//! Generic over [`FoldRing`] so the same driver works with the N=256
//! commitment ring (`Cyclo256Ring`) for fast development and per-channel
//! N=8192 rings (`pvthfhe_rings::FheMathRing`) for production.
//!
//! Each channel gets its own ring instance and fold accumulator; the
//! driver applies one fold step per channel per batch of instances.

use crate::fold_ring::{fold_one_generic, FoldRing};
use crate::CycloError;

/// Per-channel fold state — one accumulator per channel.
#[derive(Clone, Debug)]
pub struct ChannelAccumulator<P: Clone> {
    /// Accumulated commitment.
    pub commitment: P,
    /// Accumulated witness.
    pub witness: P,
    /// Number of folds applied.
    pub fold_count: usize,
}

/// Multi-channel fold driver, generic over the ring type.
///
/// Holds one ring instance per channel plus per-channel accumulators.
/// The `fold_one` method applies a NIFS-like fold step: the new instance
/// is accumulated via ring addition (interim stub; real NIFS prover
/// integration follows with the NIFS engine genericization).
pub struct ChannelFoldDriver<R: FoldRing> {
    rings: Vec<R>,
    accumulators: Vec<ChannelAccumulator<R::Poly>>,
    #[allow(dead_code)]
    use_binary_tree: bool,
}

impl<R: FoldRing> ChannelFoldDriver<R> {
    /// Create a new driver from a collection of ring instances.
    pub fn new(rings: Vec<R>) -> Self {
        let accumulators = rings.iter().map(|r| {
            ChannelAccumulator {
                commitment: r.zero(),
                witness: r.zero(),
                fold_count: 0,
            }
        }).collect();
        Self { rings, accumulators, use_binary_tree: true }
    }

    /// Number of channels.
    pub fn channel_count(&self) -> usize { self.rings.len() }

    /// Access a ring by index.
    pub fn ring(&self, idx: usize) -> &R { &self.rings[idx] }

    /// Get the accumulator for a specific channel.
    pub fn accumulator(&self, idx: usize) -> &ChannelAccumulator<R::Poly> {
        &self.accumulators[idx]
    }

    /// Fold one set of per-channel instances into the accumulators.
    ///
    /// Each instance contributes its polynomial pair (commitment, witness)
    /// to the corresponding channel's accumulator via the ternary-challenge
    /// NIFS fold step from [`fold_one_generic`].
    pub fn fold_one(&mut self, commitments: &[R::Poly], witnesses: &[R::Poly]) -> Result<(), CycloError> {
        for (i, ring) in self.rings.iter().enumerate() {
            if ring.degree() == 0 {
                continue;
            }
            let acc = &mut self.accumulators[i];
            let inst_commitment = commitments.get(i).cloned().unwrap_or_else(|| ring.zero());
            let inst_witness = witnesses.get(i).cloned().unwrap_or_else(|| ring.zero());

            let (new_c, new_w) = fold_one_generic(
                ring,
                &acc.commitment,
                &acc.witness,
                &inst_commitment,
                &inst_witness,
            )?;
            acc.commitment = new_c;
            acc.witness = new_w;
            acc.fold_count += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fold_ring::Cyclo256Ring;

    fn make_driver() -> ChannelFoldDriver<Cyclo256Ring> {
        ChannelFoldDriver::new(vec![Cyclo256Ring, Cyclo256Ring, Cyclo256Ring])
    }

    #[test]
    fn driver_inits_with_three_channels() {
        let driver = make_driver();
        assert_eq!(driver.channel_count(), 3);
    }

    #[test]
    fn fold_increments_count() {
        let mut driver = make_driver();
        let ring = driver.ring(0);
        let zero = ring.zero();
        let commitments = vec![zero.clone(), zero.clone(), zero.clone()];
        let witnesses = vec![zero.clone(), zero.clone(), zero.clone()];
        driver.fold_one(&commitments, &witnesses).expect("fold should succeed");
        assert_eq!(driver.accumulator(0).fold_count, 1);
        assert_eq!(driver.accumulator(1).fold_count, 1);
        assert_eq!(driver.accumulator(2).fold_count, 1);
    }

    #[test]
    fn fold_nonzero_instance_increments_count() {
        let mut driver = make_driver();
        let degree = driver.ring(0).degree();
        let a_coeffs: Vec<u64> = (0..degree).map(|i| (i + 1) as u64).collect();
        let a = crate::ring::RqPoly(a_coeffs);
        let commitments = vec![a.clone(), a.clone(), a.clone()];
        let witnesses = vec![a.clone(), a.clone(), a.clone()];
        driver.fold_one(&commitments, &witnesses).expect("fold should succeed");
        assert_eq!(driver.accumulator(0).fold_count, 1);
        assert_eq!(driver.accumulator(1).fold_count, 1);
        assert_eq!(driver.accumulator(2).fold_count, 1);
    }
}
