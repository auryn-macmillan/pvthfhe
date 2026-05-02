use super::types::{DkgTranscript, PartyId, Round1Message, Round2Message, Round3Aggregate};
use pvthfhe_fhe::{mock::MockBackend, FheBackend, PublicKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FaultType {
    MalformedProof,
    WithholdShare,
    Equivocate,
}

#[derive(Debug)]
pub enum KeygenResult {
    Complete(DkgTranscript),
    Blamed(Vec<PartyId>),
}

pub struct KeygenSimulator {
    n_parties: usize,
    _threshold: usize,
    backend: MockBackend,
    faults: HashMap<PartyId, FaultType>,
}

fn party_id_from_index(index: usize) -> PartyId {
    u32::try_from(index).unwrap_or(u32::MAX)
}

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

impl KeygenSimulator {
    pub fn new(n_parties: usize, threshold: usize, backend: MockBackend) -> Self {
        Self {
            n_parties,
            _threshold: threshold,
            backend,
            faults: HashMap::new(),
        }
    }

    pub fn inject_fault(&mut self, party_id: PartyId, fault: FaultType) {
        self.faults.insert(party_id, fault);
    }

    pub fn run(&mut self) -> Result<KeygenResult, pvthfhe_fhe::FheError> {
        // ROUND 1
        let mut r1_msgs = Vec::new();
        let mut equivocated = HashSet::new();

        for i in 0..self.n_parties {
            let party_id = party_id_from_index(i);
            let fault = self.faults.get(&party_id);

            // Generate normal message
            let mut msg = self.generate_r1_msg(party_id)?;

            // Apply faults
            if fault == Some(&FaultType::MalformedProof) {
                msg.nizk = vec![0xba, 0xad]; // Malformed
            } else if fault == Some(&FaultType::WithholdShare) {
                msg.encrypted_shares.clear(); // Withhold
            }

            r1_msgs.push(msg.clone());

            if fault == Some(&FaultType::Equivocate) {
                let mut alt_msg = msg.clone();
                alt_msg.commitment = hash_bytes(b"alt");
                r1_msgs.push(alt_msg);
                equivocated.insert(party_id);
            }
        }

        // AGGREGATOR CHECK ROUND 1
        let mut blames = Vec::new();
        let mut valid_r1 = Vec::new();
        let mut seen = HashSet::new();
        let mut duplicates = HashSet::new();

        for msg in &r1_msgs {
            if !seen.insert(msg.party_id) {
                duplicates.insert(msg.party_id);
            }
        }

        for msg in &r1_msgs {
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
            // For WithholdShare, another party will complain in Round 2
            valid_r1.push(msg.clone());
        }

        if !blames.is_empty() {
            blames.sort();
            return Ok(KeygenResult::Blamed(blames));
        }

        // ROUND 2
        let mut r2_msgs = Vec::new();
        for i in 0..self.n_parties {
            let party_id = party_id_from_index(i);
            if blames.contains(&party_id) {
                continue;
            }
            let mut complaints = Vec::new();
            for r1 in &valid_r1 {
                if r1.party_id == party_id {
                    continue;
                }
                if !r1.encrypted_shares.contains_key(&party_id) {
                    complaints.push(r1.party_id);
                }
            }
            r2_msgs.push(Round2Message {
                party_id,
                complaints,
            });
        }

        // AGGREGATOR CHECK ROUND 2
        for r2 in &r2_msgs {
            for &c in &r2.complaints {
                if !blames.contains(&c) {
                    blames.push(c);
                }
            }
        }

        if !blames.is_empty() {
            blames.sort();
            return Ok(KeygenResult::Blamed(blames));
        }

        // ROUND 3
        let participant_set: Vec<PartyId> = valid_r1.iter().map(|m| m.party_id).collect();
        let mut shares = Vec::new();
        for r1 in &valid_r1 {
            shares.push(pvthfhe_fhe::KeygenShare {
                party_id: r1.party_id,
                bytes: r1.pk_i.bytes.clone(),
            });
        }

        let aggregate_pk = self.backend.aggregate_keygen(&shares)?;

        // Merkle root and hash mock
        let mut p_set_bytes = Vec::new();
        for p in &participant_set {
            p_set_bytes.extend_from_slice(&p.to_be_bytes());
        }
        let participant_set_hash = hash_bytes(&p_set_bytes);

        // Sort round 1 messages for transcript (by party_id)
        valid_r1.sort_by_key(|m| m.party_id);

        let mut dkg_root_hasher = Sha256::new();
        for m in &valid_r1 {
            let mut leaf = Vec::new();
            leaf.extend_from_slice(&m.party_id.to_be_bytes());
            leaf.extend_from_slice(&m.pk_i_hash);
            dkg_root_hasher.update(hash_bytes(&leaf));
        }
        let mut dkg_root = [0u8; 32];
        dkg_root.copy_from_slice(&dkg_root_hasher.finalize());

        let mut transcript_hasher = Sha256::new();
        transcript_hasher.update(b"mock_cbor_hash_of_everything");
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
            },
            dkg_root,
            transcript_hash,
        };

        Ok(KeygenResult::Complete(transcript))
    }

    fn generate_r1_msg(&self, party_id: PartyId) -> Result<Round1Message, pvthfhe_fhe::FheError> {
        let mut rng = OsRng;
        let share = self.backend.keygen_share(party_id, &mut rng)?;
        let pk_i = PublicKey { bytes: share.bytes };
        let pk_i_hash = hash_bytes(&pk_i.bytes);

        let mut encrypted_shares = HashMap::new();
        for j in 0..self.n_parties {
            let j = party_id_from_index(j);
            if j != party_id {
                encrypted_shares.insert(j, vec![0x11, 0x22]);
            }
        }

        Ok(Round1Message {
            party_id,
            pk_i,
            pk_i_hash,
            commitment: hash_bytes(&party_id.to_be_bytes()),
            poly_commit: hash_bytes(&party_id.to_be_bytes()),
            encrypted_shares,
            nizk: vec![0x00, 0x01], // valid
        })
    }
}
