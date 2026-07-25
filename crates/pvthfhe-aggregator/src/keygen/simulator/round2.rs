//! Round 2: complaint generation — each party complains about dealers whose
//! Round 1 message lacks an encrypted share addressed to them.

use super::super::types::{PartyId, Round1Message, Round2Message};
use super::{party_id_from_index, KeygenSimulator};

impl KeygenSimulator {
    /// Drive Round 2: collect each non-blamed party's complaints about dealers
    /// that withheld their encrypted share.
    pub(super) fn generate_round2_messages(
        &self,
        valid_r1: &[Round1Message],
        blames: &[PartyId],
    ) -> Vec<Round2Message> {
        let mut r2_msgs = Vec::new();
        for i in 0..self.n_parties {
            let party_id = party_id_from_index(i);
            if blames.contains(&party_id) {
                continue;
            }
            let mut complaints = Vec::new();
            for r1 in valid_r1 {
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
        r2_msgs
    }
}
