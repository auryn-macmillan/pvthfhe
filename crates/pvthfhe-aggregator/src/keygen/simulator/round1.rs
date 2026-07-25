//! Round 1: message generation (dealing), injected-fault application, H2
//! commit-reveal binding, and per-recipient share encryption.

use super::super::types::{PartyId, Round1Message};
use super::{
    compute_round1_commitment, hash_bytes, party_id_from_index, FaultType, KeygenSimulator,
};
use anyhow::Context;
use pvthfhe_fhe::PublicKey;
use pvthfhe_foundations::domain_tags::Tag;
use rand_chacha::ChaCha8Rng;
use rand_core::{OsRng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

impl KeygenSimulator {
    /// Drive Round 1: generate each party's message, apply injected faults,
    /// and record equivocators that broadcast a conflicting second message.
    pub(super) fn generate_round1_messages(
        &self,
        session_id: &[u8; 32],
        all_pks: &HashMap<PartyId, PublicKey>,
    ) -> Result<(Vec<Round1Message>, HashSet<PartyId>), pvthfhe_fhe::FheError> {
        let mut r1_msgs = Vec::new();
        let mut equivocated = HashSet::new();

        for i in 0..self.n_parties {
            let party_id = party_id_from_index(i);
            let fault = self.faults.get(&party_id);

            // Generate normal message
            let mut msg = self.generate_r1_msg(session_id, party_id, all_pks)?;

            // Apply faults
            if fault == Some(&FaultType::MalformedProof) {
                msg.nizk = vec![0xba, 0xad]; // Malformed
            } else if fault == Some(&FaultType::WithholdShare) {
                msg.encrypted_shares.clear(); // Withhold
            }

            r1_msgs.push(msg.clone());

            if fault == Some(&FaultType::Equivocate) {
                let mut alt_msg = msg.clone();
                alt_msg.commitment = hash_bytes(b"equivocation-alt/v1", b"alt");
                r1_msgs.push(alt_msg);
                equivocated.insert(party_id);
            }
        }

        Ok((r1_msgs, equivocated))
    }

    fn generate_r1_msg(
        &self,
        session_id: &[u8; 32],
        party_id: PartyId,
        all_pks: &HashMap<PartyId, PublicKey>,
    ) -> Result<Round1Message, pvthfhe_fhe::FheError> {
        let share = self.keygen_share_with_session(session_id, party_id)?;
        let pk_i = PublicKey {
            bytes: share.bytes.0.clone(),
        };
        let pk_i_hash = hash_bytes(b"participant-pk-hash/v1", pk_i.bytes.as_slice());

        // Generate real BFV keypair correctness NIZK (C0). The current
        // Round1Message wire slot carries the per-recipient encrypted-share
        // proof bundle below; keep this proof generation here as a fail-fast
        // simulator self-check until the transcript schema grows a distinct C0
        // proof field.
        let _keygen_nizk = self
            .generate_keygen_nizk(session_id, party_id, &pk_i, &share)
            .map_err(|e| pvthfhe_fhe::FheError::Backend { reason: e })?;

        let mut encrypted_shares = HashMap::new();
        let mut nizk_proofs: Vec<Vec<u8>> = Vec::new();

        for j in 0..self.n_parties {
            let recipient_id = party_id_from_index(j);
            if recipient_id != party_id {
                match all_pks.get(&recipient_id) {
                    Some(recipient_pk) => {
                        let (ct_bytes, nizk_bytes) = self.encrypt_share_for_recipient(
                            session_id,
                            party_id,
                            recipient_id,
                            recipient_pk,
                        )?;
                        encrypted_shares.insert(recipient_id, ct_bytes);
                        nizk_proofs.push(nizk_bytes);
                    }
                    None => {
                        return Err(pvthfhe_fhe::FheError::Backend {
                            reason: format!(
                                "recipient {} has no public key registered in all_pks",
                                recipient_id
                            ),
                        });
                    }
                }
            }
        }

        // H2: fresh nonce for rogue-key commit-reveal binding.
        let commitment_nonce = {
            let mut nonce = [0u8; 32];
            OsRng.fill_bytes(&mut nonce);
            nonce
        };
        // H2: commitment binds pk_i_hash + nonce to prevent an adversary from
        // choosing their pk after seeing honest keys.
        let commitment =
            { compute_round1_commitment(party_id, session_id, &pk_i_hash, &commitment_nonce) };

        let nizk =
            serialize_nizk_bundle(&nizk_proofs).map_err(|e| pvthfhe_fhe::FheError::Backend {
                reason: format!("serialize encrypted-share NIZK bundle: {e}"),
            })?;

        Ok(Round1Message {
            party_id,
            pk_i,
            pk_i_hash,
            commitment_nonce,
            commitment,
            poly_commit: {
                let mut data = Vec::new();
                data.extend_from_slice(session_id);
                data.extend_from_slice(&party_id.to_be_bytes());
                data.extend_from_slice(&share.bytes.0);
                hash_bytes(b"poly-commit/v1", &data)
            },
            encrypted_shares,
            nizk,
        })
    }

    fn encrypt_share_for_recipient(
        &self,
        session_id: &[u8; 32],
        dealer_id: PartyId,
        recipient_id: PartyId,
        recipient_pk: &PublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>), pvthfhe_fhe::FheError> {
        let mut hasher = Sha256::new();
        hasher.update(Tag::SimShare.as_bytes());
        hasher.update(session_id);
        hasher.update(&dealer_id.to_be_bytes());
        hasher.update(&recipient_id.to_be_bytes());
        let share_hash: [u8; 32] = hasher.finalize().into();

        let mut hasher = Sha256::new();
        hasher.update(Tag::SimEncrypt.as_bytes());
        hasher.update(session_id);
        hasher.update(&dealer_id.to_be_bytes());
        hasher.update(&recipient_id.to_be_bytes());
        let encrypt_seed: [u8; 32] = hasher.finalize().into();
        let mut encrypt_rng = ChaCha8Rng::from_seed(encrypt_seed); // allow-seeded-rng: deterministic simulator

        let ct = self
            .backend
            .encrypt(recipient_pk, &share_hash, &mut encrypt_rng)
            .map_err(|e| pvthfhe_fhe::FheError::Backend {
                reason: format!("encrypt share for recipient {recipient_id}: {e}"),
            })?;

        let nizk = self
            .prove_keygen_nizk(session_id, dealer_id, recipient_id, &ct, &share_hash)
            .map_err(|e| pvthfhe_fhe::FheError::Backend {
                reason: e.to_string(),
            })?;

        Ok((ct.bytes, nizk))
    }
}

fn serialize_nizk_bundle(proofs: &[Vec<u8>]) -> anyhow::Result<Vec<u8>> {
    let count = u16::try_from(proofs.len()).context("proof count exceeds u16")?;
    let mut buf = Vec::new();
    buf.extend_from_slice(&count.to_be_bytes());
    for proof in proofs {
        let len = u32::try_from(proof.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(proof);
    }
    Ok(buf)
}
