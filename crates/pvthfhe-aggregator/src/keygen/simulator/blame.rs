//! Aggregator verification checks: Round 1 blame detection (NonEquiv
//! equivocators, duplicates, malformed NIZKs, H2 commitment binding) and
//! Round 2 complaint collection, plus the ciphertext memory-clearing
//! threshold applied to surviving Round 1 messages.

use super::super::types::{PartyId, Round1Message, Round2Message};
use super::{compute_round1_commitment, KeygenSimulator};
use std::collections::HashSet;

impl KeygenSimulator {
    /// AGGREGATOR CHECK ROUND 1 — uses canonical_r1_msgs (r1_msgs dropped
    /// upstream). Returns the Round 1 messages that survive verification.
    pub(super) fn aggregator_check_round1(
        &self,
        canonical_r1_msgs: Vec<Round1Message>,
        equivocated: &HashSet<PartyId>,
        session_id: &[u8; 32],
        blames: &mut Vec<PartyId>,
    ) -> Vec<Round1Message> {
        // Propagate NonEquiv-detected equivocators to blame list.
        for &eq in equivocated {
            if !blames.contains(&eq) {
                blames.push(eq);
            }
        }
        let mut valid_r1 = Vec::new();
        let mut seen = HashSet::new();
        let mut duplicates = HashSet::new();

        for msg in &canonical_r1_msgs {
            if !seen.insert(msg.party_id) {
                duplicates.insert(msg.party_id);
            }
        }

        for msg in &canonical_r1_msgs {
            // Skip parties already blamed for equivocation above
            if blames.contains(&msg.party_id) {
                continue;
            }
            if duplicates.contains(&msg.party_id) {
                if !blames.contains(&msg.party_id) {
                    blames.push(msg.party_id);
                }
                continue;
            }
            if msg.nizk == vec![0xba, 0xad] {
                if !blames.contains(&msg.party_id) {
                    blames.push(msg.party_id);
                }
                continue;
            }
            // H2: verify commit-reveal binding to prevent rogue-key attacks.
            let expected_commitment = compute_round1_commitment(
                msg.party_id,
                session_id,
                &msg.pk_i_hash,
                &msg.commitment_nonce,
            );
            if msg.commitment != expected_commitment {
                blames.push(msg.party_id);
                continue;
            }
            // For WithholdShare, another party will complain in Round 2
            valid_r1.push(msg.clone());
        }
        // MEMORY: clear encrypted_shares ciphertexts — Round 2 only needs
        // key presence (contains_key), not the actual ciphertext bytes.
        // This frees n×(n-1) BFV ciphertexts (~392 KB each with real backend),
        // which is ~25 GB at n=255 but negligible for small ceremonies.
        // Below the threshold the shares are kept so callers (and tests) can
        // inspect the transcript.
        const EST_CIPHERTEXT_BYTES: usize = 392_000;
        const CLEAR_THRESHOLD_BYTES: usize = 256 * 1024 * 1024;
        let estimated_bytes =
            self.n_parties * self.n_parties.saturating_sub(1) * EST_CIPHERTEXT_BYTES;
        if estimated_bytes > CLEAR_THRESHOLD_BYTES {
            for msg in &mut valid_r1 {
                msg.encrypted_shares.values_mut().for_each(|v| v.clear());
            }
        }
        std::mem::drop(canonical_r1_msgs);
        valid_r1
    }

    /// AGGREGATOR CHECK ROUND 2
    pub(super) fn aggregator_check_round2(r2_msgs: &[Round2Message], blames: &mut Vec<PartyId>) {
        for r2 in r2_msgs {
            for &c in &r2.complaints {
                if !blames.contains(&c) {
                    blames.push(c);
                }
            }
        }
    }
}
