//! Round 3: key aggregation, C5 aggregate public-key formation proof, Merkle
//! root and transcript-hash computation, and final transcript assembly.

use super::super::types::{DkgTranscript, PartyId, Round1Message, Round2Message, Round3Aggregate};
use super::{hash_bytes, party_id_from_index, KeygenResult, KeygenSimulator};
use pvthfhe_fhe::PublicKey;
use pvthfhe_foundations::domain_tags::Tag;
use pvthfhe_foundations::types::ProtocolBytes;
use pvthfhe_non_equiv::NonEquivProof;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};

impl KeygenSimulator {
    /// Drive Round 3: aggregate the surviving key shares, build the C5
    /// formation proof, and assemble the final DKG transcript.
    pub(super) fn finalize_round3(
        &self,
        mut valid_r1: Vec<Round1Message>,
        r2_msgs: Vec<Round2Message>,
        all_pks: &HashMap<PartyId, PublicKey>,
        session_id: &[u8; 32],
        non_equiv_proofs: HashMap<PartyId, NonEquivProof>,
        blames: Vec<PartyId>,
        round_timeout: Option<Duration>,
    ) -> Result<KeygenResult, pvthfhe_fhe::FheError> {
        let round_start = Instant::now();
        let participant_set: Vec<PartyId> = valid_r1.iter().map(|m| m.party_id).collect();
        let mut shares = Vec::new();
        for r1 in &valid_r1 {
            shares.push(pvthfhe_fhe::KeygenShare {
                party_id: r1.party_id,
                bytes: ProtocolBytes(r1.pk_i.bytes.clone()),
            });
        }

        let aggregate_pk = self.backend.aggregate_keygen(&shares)?;

        // C5: Aggregate public-key formation proof with per-participant PoP.
        let c5_proof_root = {
            let mut pops = Vec::new();
            for share in &shares {
                let pk_i = all_pks
                    .get(&share.party_id)
                    .cloned()
                    .unwrap_or_else(|| PublicKey {
                        bytes: share.bytes.0.clone(),
                    });
                let mut nonce = [0u8; 32];
                OsRng.fill_bytes(&mut nonce);
                let pop = super::super::c5_proof::generate_pop(
                    share.party_id,
                    session_id,
                    &pk_i.bytes,
                    share.bytes.0.clone(),
                    nonce,
                );
                pops.push(pop);
            }
            let pks: Vec<PublicKey> = shares
                .iter()
                .map(|s| {
                    all_pks
                        .get(&s.party_id)
                        .cloned()
                        .unwrap_or_else(|| PublicKey {
                            bytes: s.bytes.0.clone(),
                        })
                })
                .collect();
            let proof = super::super::c5_proof::bundle_c5_proof(
                &pks,
                &aggregate_pk,
                pops,
                self.participant_set_hash(),
            );
            super::super::c5_proof::compute_c5_proof_root(&proof)
        };

        // Merkle root and hash mock
        let participant_set_hash = self.participant_set_hash();

        // Sort round 1 messages for transcript (by party_id)
        valid_r1.sort_by_key(|m| m.party_id);

        let mut dkg_root_hasher = Sha256::new();
        for m in &valid_r1 {
            let mut leaf = Vec::new();
            leaf.extend_from_slice(&m.party_id.to_be_bytes());
            leaf.extend_from_slice(&m.pk_i_hash);
            dkg_root_hasher.update(hash_bytes(b"dkg-root/v1", &leaf));
        }
        let mut dkg_root = [0u8; 32];
        dkg_root.copy_from_slice(&dkg_root_hasher.finalize());

        let mut transcript_hasher = Sha256::new();
        transcript_hasher.update(Tag::Transcript.as_bytes());
        // Serialize round1_messages for transcript hash
        for msg in &valid_r1 {
            transcript_hasher.update(&msg.party_id.to_be_bytes());
            transcript_hasher.update(&msg.nizk);
            transcript_hasher.update(&msg.pk_i.bytes);
            transcript_hasher.update(&msg.pk_i_hash);
            transcript_hasher.update(&msg.commitment_nonce);
            transcript_hasher.update(&msg.commitment);
            transcript_hasher.update(&msg.poly_commit);
            // Skip encrypted_shares to avoid ordering issues across parties
        }
        let mut transcript_hash = [0u8; 32];
        transcript_hash.copy_from_slice(&transcript_hasher.finalize());

        let transcript = DkgTranscript {
            version: 1,
            participant_set,
            round1_messages: valid_r1,
            round2_messages: r2_msgs,
            round3_aggregate: Round3Aggregate {
                aggregate_pk,
                participant_set_hash,
                c5_proof_root,
            },
            dkg_root,
            transcript_hash,
            non_equiv_proofs,
        };

        // Round 3 timeout check
        if let Some(timeout) = round_timeout {
            if round_start.elapsed() > timeout {
                let pending: Vec<PartyId> = (0..self.n_parties)
                    .map(party_id_from_index)
                    .filter(|id| !shares.iter().any(|s| s.party_id == *id) && !blames.contains(id))
                    .collect();
                return Err(pvthfhe_fhe::FheError::Backend {
                    reason: format!(
                        "round 3 timed out after {:?}: {} pending parties",
                        round_start.elapsed(),
                        pending.len()
                    ),
                });
            }
        }

        Ok(KeygenResult::Complete(transcript))
    }
}
