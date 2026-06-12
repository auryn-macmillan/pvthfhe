//! Weak Leader Election for permissionless aggregator selection.
//! ePrint 2026/1159 §7, Algorithm 6 — adapted for synchronous setting.

use sha2::{Digest, Sha256};

const DOMAIN_SEPARATOR: &[u8] = b"pvthfhe-leader-election/v1";

/// A provably random rank for a party. Derived from a seed and party_id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvableRank {
    pub party_id: u32,
    /// Rank value (256-bit hash). Higher = better.
    pub rank: [u8; 32],
    /// Proof = SHA256(seed || party_id). Publicly verifiable.
    pub proof: LeaderElectionProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaderElectionProof {
    pub seed: [u8; 32],
    pub party_id: u32,
}

/// Result of a weak leader election.
#[derive(Clone, Debug)]
pub struct ElectionResult {
    /// The elected leader's party_id.
    pub leader_id: u32,
    /// All ranks, sorted by rank (highest first).
    pub rankings: Vec<ProvableRank>,
}

/// Generate a provable rank for a party given an election seed.
/// The rank binds to `session_id` to prevent cross-session replay.
pub fn generate_rank(seed: &[u8; 32], party_id: u32, session_id: &[u8]) -> ProvableRank {
    let mut h = Sha256::new();
    h.update(DOMAIN_SEPARATOR);
    h.update(b":rank:");
    h.update(session_id);
    h.update(seed);
    h.update(&party_id.to_be_bytes());
    let rank: [u8; 32] = h.finalize().into();
    ProvableRank {
        party_id,
        rank,
        proof: LeaderElectionProof {
            seed: *seed,
            party_id,
        },
    }
}

/// Verify that a rank was correctly generated.
pub fn rank_verify(rank: &ProvableRank, session_id: &[u8]) -> bool {
    let expected = generate_rank(&rank.proof.seed, rank.proof.party_id, session_id);
    expected.rank == rank.rank
}

/// Run a weak leader election: generate ranks for all parties, select highest.
/// Returns the leader and all rankings sorted by rank descending.
pub fn elect_leader(seed: &[u8; 32], participant_ids: &[u32], session_id: &[u8]) -> ElectionResult {
    let mut rankings: Vec<ProvableRank> = participant_ids
        .iter()
        .map(|&id| generate_rank(seed, id, session_id))
        .collect();
    // Sort descending by rank (highest first)
    rankings.sort_by(|a, b| b.rank.cmp(&a.rank));
    ElectionResult {
        leader_id: rankings[0].party_id,
        rankings,
    }
}

/// Deterministic leader election — select the participant with the highest
/// `SHA256(seed || session_id || party_id)` value.
pub fn deterministic_leader(seed: &[u8; 32], participant_ids: &[u32], session_id: &[u8]) -> u32 {
    let result = elect_leader(seed, participant_ids, session_id);
    result.leader_id
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SESSION: &[u8] = b"test-session";

    // ── F3 RED: session binding tests ──────────────────────────────────────

    #[test]
    fn test_rank_binds_session() {
        let seed = [0x42; 32];
        let r1 = generate_rank(&seed, 7, b"session-A");
        let r2 = generate_rank(&seed, 7, b"session-B");
        assert_ne!(
            r1.rank, r2.rank,
            "different session must produce different rank"
        );
    }

    #[test]
    fn test_cross_session_rank_replay_rejected() {
        let seed = [0x42; 32];
        let rank_a = generate_rank(&seed, 5, b"session-A");
        let rank_b = generate_rank(&seed, 5, b"session-B");
        assert!(
            !rank_verify(&rank_a, b"session-B"),
            "rank from session A must not verify in session B"
        );
        // Also check the negative case: rank_a verifies in session-A
        assert!(rank_verify(&rank_a, b"session-A"));
        // rank_b does NOT verify in session-A
        assert!(!rank_verify(&rank_b, b"session-A"));
    }

    #[test]
    fn test_elect_leader_session_binding() {
        let seed = [0x42; 32];
        let ids: Vec<u32> = (1..=5).collect();
        let r1 = elect_leader(&seed, &ids, b"session-A");
        let r2 = elect_leader(&seed, &ids, b"session-B");
        // Leaders may differ across sessions
        // At minimum, leader is in participant set
        assert!(ids.contains(&r1.leader_id));
        assert!(ids.contains(&r2.leader_id));
    }

    // ── Existing tests updated with TEST_SESSION ───────────────────────────

    #[test]
    fn test_rank_deterministic() {
        let seed = [0x42; 32];
        let r1 = generate_rank(&seed, 7, TEST_SESSION);
        let r2 = generate_rank(&seed, 7, TEST_SESSION);
        assert_eq!(r1.rank, r2.rank);
    }

    #[test]
    fn test_different_parties_different_ranks() {
        let seed = [0x42; 32];
        let r1 = generate_rank(&seed, 1, TEST_SESSION);
        let r2 = generate_rank(&seed, 2, TEST_SESSION);
        assert_ne!(r1.rank, r2.rank);
    }

    #[test]
    fn test_rank_verify() {
        let seed = [0x42; 32];
        let rank = generate_rank(&seed, 5, TEST_SESSION);
        assert!(rank_verify(&rank, TEST_SESSION));
    }

    #[test]
    fn test_tampered_rank_rejected() {
        let seed = [0x42; 32];
        let mut rank = generate_rank(&seed, 5, TEST_SESSION);
        rank.rank = [0xFF; 32];
        assert!(!rank_verify(&rank, TEST_SESSION));
    }

    #[test]
    fn test_elect_leader_consistency() {
        let seed = [0x42; 32];
        let ids: Vec<u32> = (1..=5).collect();
        let r1 = elect_leader(&seed, &ids, TEST_SESSION);
        let r2 = elect_leader(&seed, &ids, TEST_SESSION);
        assert_eq!(r1.leader_id, r2.leader_id);
    }

    #[test]
    fn test_elect_leader_all_ids_in_rankings() {
        let seed = [0x99; 32];
        let ids: Vec<u32> = (1..=10).collect();
        let result = elect_leader(&seed, &ids, TEST_SESSION);
        assert_eq!(result.rankings.len(), 10);
        let mut found_ids: Vec<u32> = result.rankings.iter().map(|r| r.party_id).collect();
        found_ids.sort();
        assert_eq!(found_ids, ids);
    }

    #[test]
    fn test_leader_is_in_participant_set() {
        let seed = [0xAB; 32];
        let ids: Vec<u32> = vec![10, 20, 30, 40];
        let result = elect_leader(&seed, &ids, TEST_SESSION);
        assert!(ids.contains(&result.leader_id));
    }
}
