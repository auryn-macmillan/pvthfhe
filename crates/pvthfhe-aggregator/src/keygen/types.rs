use pvthfhe_fhe::PublicKey;

pub type PartyId = u32;

#[derive(Clone, Debug)]
pub struct Round1Message {
    pub party_id: PartyId,
    pub pk_i: PublicKey,
    pub pk_i_hash: [u8; 32],
    /// Fresh random nonce binding the commitment to prevent rogue-key attacks (H2).
    pub commitment_nonce: [u8; 32],
    /// Commitment = SHA256("pvthfhe-dkg-commit-reveal/v2" || party_id || session_id || pk_i_hash || nonce).
    pub commitment: [u8; 32],
    pub poly_commit: [u8; 32],
    pub encrypted_shares: std::collections::HashMap<PartyId, Vec<u8>>,
    pub nizk: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Round2Message {
    pub party_id: PartyId,
    pub complaints: Vec<PartyId>, // Simplified for simulator
}

#[derive(Clone, Debug)]
pub struct Round3Aggregate {
    pub aggregate_pk: PublicKey,
    pub participant_set_hash: [u8; 32],
    pub c5_proof_root: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct DkgTranscript {
    pub version: u8,
    pub participant_set: Vec<PartyId>,
    pub round1_messages: Vec<Round1Message>,
    pub round2_messages: Vec<Round2Message>,
    pub round3_aggregate: Round3Aggregate,
    pub dkg_root: [u8; 32],
    pub transcript_hash: [u8; 32],
}

pub enum KeygenState {
    Round1,
    Round2 {
        round1_msgs: Vec<Round1Message>,
    },
    Round3 {
        round1_msgs: Vec<Round1Message>,
        round2_msgs: Vec<Round2Message>,
    },
    Complete {
        transcript: DkgTranscript,
    },
    Failed {
        blame: Vec<PartyId>,
    },
}
