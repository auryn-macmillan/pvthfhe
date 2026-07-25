//! Prover side of the RLWE sigma protocol (single-round and parallel repetition).

use rand_core::RngCore;

use crate::NizkError;

use super::challenge::{derive_challenge_from_commitment, derive_transcript_commitment};
use super::sample::{sample_bounded, scalar_mul_i64};
use super::{
    int_poly_to_rns, num_rns_limbs, poly_mul_rq, rlwe_context, rlwe_n, rns_add, SigmaMultiProof,
    SigmaProof, SigmaStatement, SigmaWitness, B_Y, REJECTION_M,
};

/// Produce a sigma proof for statement (c, d_i) and witness (s_i, e_i).
///
/// `session_id` and `participant_id` are bound into the Fiat-Shamir transcript
/// via the locked domain separator from [`crate::fiat_shamir::Transcript`].
pub fn prove(
    session_id: &[u8],
    participant_id: u32,
    stmt: &SigmaStatement,
    wit: &SigmaWitness,
    rng: &mut dyn RngCore,
    d_commitment: &[u8; 32],
) -> Result<SigmaProof, NizkError> {
    prove_round(session_id, participant_id, stmt, wit, rng, d_commitment, 0)
}

/// Produce a sigma proof for statement (c, d_i) and witness (s_i, e_i)
/// with `round_index` bound into the Fiat-Shamir transcript.
///
/// Used internally by [`prove_multi`] to create per-round proofs with
/// round-index domain separation.
fn prove_round(
    session_id: &[u8],
    participant_id: u32,
    stmt: &SigmaStatement,
    wit: &SigmaWitness,
    rng: &mut dyn RngCore,
    d_commitment: &[u8; 32],
    round_index: usize,
) -> Result<SigmaProof, NizkError> {
    let n = rlwe_n();
    let rns_len = n * num_rns_limbs();
    if stmt.c_rns.len() != rns_len || stmt.d_rns.len() != rns_len {
        return Err(NizkError::InvalidInput {
            reason: "statement RNS lengths must be L*N",
            party_id: None,
        });
    }
    if wit.s_i.len() != n || wit.e_i.len() != n {
        return Err(NizkError::InvalidInput {
            reason: "witness polynomials must have length N",
            party_id: None,
        });
    }
    let ctx = rlwe_context()?;

    #[cfg(test)]
    const MAX_REJECTION_RETRIES: usize = 5;
    #[cfg(not(test))]
    const MAX_REJECTION_RETRIES: usize = 100_000;

    for _attempt in 0..MAX_REJECTION_RETRIES {
        let y_s = sample_bounded(rng, n, B_Y)?;
        let y_e = sample_bounded(rng, n, B_Y)?;

        let y_s_rns = int_poly_to_rns(&y_s, ctx)?;
        let y_e_rns = int_poly_to_rns(&y_e, ctx)?;
        let c_ys_rns = poly_mul_rq(&stmt.c_rns, &y_s_rns, ctx)?;
        let t_rns = rns_add(&c_ys_rns, &y_e_rns, ctx)?;

        let transcript_commitment = derive_transcript_commitment(&t_rns, &stmt.c_rns, &stmt.d_rns);
        let ch = derive_challenge_from_commitment(
            &transcript_commitment,
            session_id,
            participant_id,
            round_index,
            d_commitment,
        )?;

        let z_s: Vec<i64> = y_s
            .iter()
            .zip(wit.s_i.iter())
            .map(|(&a, &b)| a + scalar_mul_i64(ch, b))
            .collect();
        let z_e: Vec<i64> = y_e
            .iter()
            .zip(wit.e_i.iter())
            .map(|(&a, &b)| a + scalar_mul_i64(ch, b))
            .collect();

        // Lyubashevsky 2009, Lemma 4: reject with probability
        // 1 - exp((-2*ch*<y,s> - ||ch*s||²) / (2 * M * σ²))
        // For scalar challenge ch ∈ {-1,0,1}:
        let ys_dot: f64 = y_s
            .iter()
            .zip(wit.s_i.iter())
            .map(|(&a, &b)| (a as f64) * (b as f64))
            .sum();
        let ch_f64 = ch as f64;
        let s_norm_sq: f64 = wit.s_i.iter().map(|&x| (x as f64) * (x as f64)).sum();
        let exponent = (-2.0 * ch_f64 * ys_dot - ch_f64 * ch_f64 * s_norm_sq)
            / (2.0 * REJECTION_M * (B_Y as f64).powi(2));
        let accept_prob = exponent.exp();

        let mut sample_bytes = [0u8; 8];
        rng.fill_bytes(&mut sample_bytes);
        let raw = u64::from_le_bytes(sample_bytes);
        let sample = (raw as f64) / (u64::MAX as f64);

        if sample < accept_prob {
            return Ok(SigmaProof {
                t_rns,
                z_s,
                z_e,
                ch,
            });
        }
    }
    Err(NizkError::ProofGenerationFailed {
        reason: "sigma rejection sampling exhausted all retries",
        party_id: None,
    })
}

/// Produce k independent sigma proofs via parallel repetition.
///
/// Each round uses a fresh masking vector (y_s, y_e) and independently-derived
/// challenge. The round index `i ∈ {0..num_rounds}` is bound into the Fiat-Shamir
/// transcript to prevent cross-round replay.
///
/// Soundness error = (2/3)^num_rounds.
pub fn prove_multi(
    session_id: &[u8],
    participant_id: u32,
    stmt: &SigmaStatement,
    wit: &SigmaWitness,
    rng: &mut dyn RngCore,
    d_commitment: &[u8; 32],
    num_rounds: usize,
) -> Result<SigmaMultiProof, NizkError> {
    let mut rounds = Vec::with_capacity(num_rounds);
    for i in 0..num_rounds {
        let proof = prove_round(session_id, participant_id, stmt, wit, rng, d_commitment, i)?;
        rounds.push(proof);
    }
    Ok(SigmaMultiProof { rounds })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::RngCore;

    /// F4 RED: rejection sampling exhaustion must return an error, not a fallback proof.
    /// Uses a deterministic counting RNG that forces rejection on every attempt
    /// to verify the prover exhausts retries and returns Err.
    #[test]
    fn test_rejection_sampling_exhausts_retries_returns_error() {
        use std::cell::Cell;

        let n = rlwe_n();
        let sample_quota: usize = 2 * n;

        // CountingRng: during the `sample_quota` sampling phase, fills with
        // B_Y (16384) LE bytes so sample_bounded returns y = B_Y - B_Y = 0.
        // With y=0, ys_dot=0 and accept_prob ≤ 1.0 for all challenges,
        // so the rejection check (filling with u64::MAX) always rejects.
        struct CountingRng<'a> {
            remaining_samples: &'a Cell<usize>,
            reset_quota: usize,
        }
        impl RngCore for CountingRng<'_> {
            fn next_u32(&mut self) -> u32 {
                0
            }
            fn next_u64(&mut self) -> u64 {
                0
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                if dest.len() == 8 {
                    let n = self.remaining_samples.get();
                    if n > 0 {
                        self.remaining_samples.set(n - 1);
                        // Return B_Y = 16384 LE so sample_bounded gives y = 0.
                        dest.copy_from_slice(&16384u64.to_le_bytes());
                    } else {
                        // Rejection check: fill with u64::MAX to force rejection.
                        dest.fill(0xFF);
                        self.remaining_samples.set(self.reset_quota);
                    }
                } else {
                    dest.fill(0);
                }
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }

        let rns_len = n * num_rns_limbs();
        let stmt = SigmaStatement {
            c_rns: vec![1u64; rns_len],
            d_rns: vec![1u64; rns_len],
        };
        let wit = SigmaWitness {
            s_i: vec![1i64; n],
            e_i: vec![1i64; n],
        };

        let remaining = Cell::new(sample_quota);
        let mut rng = CountingRng {
            remaining_samples: &remaining,
            reset_quota: sample_quota,
        };

        let result = prove_round(b"test-f4", 0, &stmt, &wit, &mut rng, &[0u8; 32], 0);
        assert!(
            result.is_err(),
            "F4: rejection sampling exhaustion must return Err, not a fallback proof. Got: {result:?}"
        );
    }
}
