//! Native per-channel relations replacing Noir circuit-based share decryption.
//!
//! These relations express the threshold decryption correctness in the native
//! ring arithmetic of each RNS channel, eliminating the Noir circuit ceiling
//! (G-N8, N=256) and the GRECO quotient-witness overhead.
//!
//! # Relation index
//!
//! | Relation | Purpose | Channel | Witness shape |
//! |----------|---------|---------|---------------|
//! | R4 | Share receipt — received share opens against committed Merkle root | per q_l | share opening + Merkle path |
//! | R6 | Decryption share — `d_j = ct0 + ct1·sk_share_j + e_sm_share_j` | per q_l | sk_share_j (short), e_sm_share_j (smudge) |
//! | R7 | CRT reconstruction + decode — `u = Σ sl·ql + u_P`, `u = Δ·m + e` | P-track (P > Q) | quotient witnesses sl, decode error e |

use pvthfhe_rings::{FheMathRing, RqPoly};

// ── R4: Share receipt ───────────────────────────────────────────────────────

/// R4 relation: verify that a received share matches a committed value.
///
/// Each recipient receives `n` shares (one per dealer). For each share,
/// the recipient verifies that the share polynomial, evaluated at their
/// identity point, matches the committed share root.
///
/// # Constraint (per channel `q_l`)
///
/// ```text
/// share_root = MerkleRoot(share_poly)
/// received_share = share_poly.evaluate_at(recipient_id)
/// ```
///
/// The Merkle binding is done via Poseidon (same transcript hash as the
/// existing Noir circuit for backward compatibility).
#[derive(Clone, Debug)]
pub struct R4ShareReceipt {
    /// Merkle root of all dealer share commitments for this channel.
    pub share_root: RqPoly,
    /// The recipient's point on the sharing polynomial (party ID as field element).
    pub recipient_id: u64,
    /// The received share (evaluation of the sharing polynomial at recipient_id).
    pub received_share: RqPoly,
    /// Merkle proof path (sibling hashes).
    pub merkle_path: Vec<RqPoly>,
    /// Leaf index in the Merkle tree.
    pub leaf_index: u64,
}

impl R4ShareReceipt {
    /// Verify the R4 relation on a given channel ring.
    ///
    /// Returns `true` if the Merkle path verifies that `received_share` is
    /// the leaf at `leaf_index` in the tree rooted at `share_root`.
    pub fn verify(&self, ring: &FheMathRing) -> bool {
        // Recompute leaf hash: Poseidon(received_share || recipient_id)
        // Current stub: check that received_share is non-zero (placeholder)
        // TODO: integrate Poseidon hash for real Merkle verification
        let zero = RqPoly::zero(ring.degree());
        if self.received_share == zero {
            return false;
        }
        // Merkle path verification (stub): check path length consistency
        if self.merkle_path.is_empty() && self.leaf_index > 0 {
            return false;
        }
        true
    }
}

// ── R6: Decryption share ────────────────────────────────────────────────────

/// R6 relation: prove correct computation of a partial decryption share.
///
/// ```text
/// d_j = ct0 + ct1 * sk_share_j + e_sm_share_j   (mod q_l, mod X^N+1)
/// ```
///
/// Where:
/// - `ct0, ct1`: public ciphertext components (from user encryption)
/// - `sk_share_j`: secret key share of party j (committed in R4)
/// - `e_sm_share_j`: smudging noise (hides the secret key-dependent term)
#[derive(Clone, Debug)]
pub struct R6DecryptionShare {
    /// Ciphertext component ct0 (public).
    pub ct0: RqPoly,
    /// Ciphertext component ct1 = a (public).
    pub ct1: RqPoly,
    /// Partial decryption share d_j (public output).
    pub decryption_share: RqPoly,
    /// Smudging noise scale parameter λ.
    pub smudge_lambda: u64,
}

impl R6DecryptionShare {
    /// Generate a decryption share (prover side).
    ///
    /// Computes `d_j = ct0 + ct1 * sk_share_j + e_sm_j` where `e_sm_j` is
    /// sampled with width λ·σ from the smudging distribution.
    pub fn prove(
        ring: &FheMathRing,
        ct0: &RqPoly,
        ct1: &RqPoly,
        sk_share: &RqPoly,
        smudge_lambda: u64,
    ) -> Self {
        // e_sm = sample_smudge(ring, lambda)
        // For now: use a zero smudge (stub — real smudge needs CSPRNG)
        let e_sm = RqPoly::zero(ring.degree());

        // d_j = ct0 + ct1 * sk_share + e_sm
        let ct1_sk = ring.mul(ct1, sk_share);
        let d_j = ring.add(&ring.add(ct0, &ct1_sk), &e_sm);

        R6DecryptionShare {
            ct0: ct0.clone(),
            ct1: ct1.clone(),
            decryption_share: d_j,
            smudge_lambda,
        }
    }

    /// Verify the R6 relation (verifier side, given committed sk_share).
    ///
    /// Checks that `d_j == ct0 + ct1 * sk_share + e_sm` for a committed
    /// `sk_share` and a norm-bound `e_sm`.
    pub fn verify(&self, ring: &FheMathRing, sk_share: &RqPoly, e_sm: &RqPoly) -> bool {
        let ct1_sk = ring.mul(&self.ct1, sk_share);
        let expected = ring.add(&ring.add(&self.ct0, &ct1_sk), e_sm);
        expected == self.decryption_share
    }
}

// ── R7: CRT reconstruction + decode ─────────────────────────────────────────

/// R7 relation: CRT reconstruct and decode the plaintext.
///
/// Given per-channel decryption shares folded into accumulators for each
/// channel, the R7 relation:
///
/// 1. CRT-reconstructs the integer plaintext from RNS residues:
///    `u = Σ_l (s_l * q_l) + u_P`, where `s_l` are quotient witnesses
///    and `u_P` is the P-track residue
///
/// 2. Decodes the plaintext:
///    `u = Δ * m + e`, where `|e| ≤ Δ/2` (centered rounding)
///
/// The quotient witnesses `s_l` must satisfy `|s_l| < Q / q_l` and the
/// decode error must satisfy `|e| ≤ Δ/2`.  Both are enforced by
/// LatticeFold+'s algebraic range proof (not by GRECO quotient witnesses).
#[derive(Clone, Debug)]
pub struct R7Reconstruction {
    /// Plaintext modulus t.
    pub t_plain: u64,
    /// BFV scaling factor Δ = floor(Q / t).
    pub delta: u64,
}

impl R7Reconstruction {
    /// Verify the R7 decode step.
    ///
    /// Given the reconstructed integer `u`, checks that `u = Δ * m + e`
    /// with `|e| ≤ Δ/2` and returns the plaintext `m`.
    pub fn decode(&self, u: &[u64], degree: usize) -> Option<Vec<u64>> {
        let mut m = vec![0u64; degree];
        let half_delta = self.delta / 2;

        for (i, &ui) in u.iter().enumerate().take(degree) {
            // m_i = round(ui / Δ)  with centered rounding
            let qi = ui / self.delta;
            let ri = ui % self.delta;
            let mi = if ri > half_delta { qi + 1 } else { qi };

            // Verify: |e_i| = |ui - Δ * mi| ≤ Δ/2
            let reconstructed = mi * self.delta;
            let error = if reconstructed > ui {
                reconstructed - ui
            } else {
                ui - reconstructed
            };
            if error > half_delta {
                return None; // decode failure
            }
            m[i] = mi;
        }
        Some(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pvthfhe_rings::ProdParams;

    fn test_ring() -> FheMathRing {
        let params = pvthfhe_rings::ChannelParams {
            degree: 8,
            modulus: ProdParams::Q0,
            decomposition_base: ProdParams::B,
            limb_count: ProdParams::LIMB_COUNT,
        };
        FheMathRing::new(params).expect("valid params")
    }

    #[test]
    fn r6_decryption_share_roundtrip() {
        let ring = test_ring();
        let ct0 = ring.poly(vec![1, 0, 0, 0, 0, 0, 0, 0]);
        let ct1 = ring.poly(vec![2, 0, 0, 0, 0, 0, 0, 0]);
        let sk = ring.poly(vec![3, 0, 0, 0, 0, 0, 0, 0]);
        let e_sm = RqPoly::zero(8);

        let share = R6DecryptionShare::prove(&ring, &ct0, &ct1, &sk, 50);
        assert!(share.verify(&ring, &sk, &e_sm));
    }

    #[test]
    fn r6_wrong_sk_rejected() {
        let ring = test_ring();
        let ct0 = ring.poly(vec![1, 0, 0, 0, 0, 0, 0, 0]);
        let ct1 = ring.poly(vec![2, 0, 0, 0, 0, 0, 0, 0]);
        let sk = ring.poly(vec![3, 0, 0, 0, 0, 0, 0, 0]);
        let wrong_sk = ring.poly(vec![9, 0, 0, 0, 0, 0, 0, 0]);
        let e_sm = RqPoly::zero(8);

        let share = R6DecryptionShare::prove(&ring, &ct0, &ct1, &sk, 50);
        assert!(!share.verify(&ring, &wrong_sk, &e_sm));
    }

    #[test]
    fn r7_decode_roundtrip() {
        let r7 = R7Reconstruction {
            t_plain: 65536,
            delta: 1u64 << 40,
        };
        let u = vec![(1u64 << 40) + 100u64]; // Δ*1 + 100 (small error)
        let m = r7.decode(&u, 1);
        assert!(m.is_some());
        assert_eq!(m.unwrap(), vec![1]);
    }

    #[test]
    fn r7_decode_centered_rounding_works() {
        let r7 = R7Reconstruction {
            t_plain: 5,
            delta: 10u64,
        };
        let m = r7
            .decode(&[55u64], 1)
            .expect("centered rounding should succeed");
        assert_eq!(m, vec![5]); // 55/10 = 5.5, round: 5 (ties break toward qi)
    }

    #[test]
    fn r4_rejects_empty_merkle_path_for_leaf() {
        let ring = test_ring();
        let r4 = R4ShareReceipt {
            share_root: ring.poly(vec![1; 8]),
            recipient_id: 1,
            received_share: ring.poly(vec![2; 8]),
            merkle_path: vec![],
            leaf_index: 1, // non-root leaf needs a path
        };
        assert!(!r4.verify(&ring));
    }
}
