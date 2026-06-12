use super::*;
use pvthfhe_aggregator::keygen::simulator::{FaultType, KeygenResult};

const N_PARTIES_NON_EQ: usize = 5;
const THRESHOLD_NON_EQ: usize = 3;

fn non_eq_simulator() -> KeygenSimulator {
    KeygenSimulator::new(N_PARTIES_NON_EQ, THRESHOLD_NON_EQ, backend_from_seed(99)).unwrap()
}

#[test]
fn non_equiv_proofs_exist_for_all_parties_in_honest_run() {
    let mut sim = non_eq_simulator();
    let result = sim.run().unwrap();

    match result {
        KeygenResult::Complete(transcript) => {
            let proofs = &transcript.non_equiv_proofs;
            assert!(
                !proofs.is_empty(),
                "non_equiv_proofs must not be empty in honest keygen"
            );
            for pid in 1..=N_PARTIES_NON_EQ as u32 {
                assert!(
                    proofs.contains_key(&pid),
                    "party {pid} must have a NonEquiv proof"
                );
            }
            for (dealer_id, proof) in proofs {
                assert_eq!(proof.dealer_id, *dealer_id, "proof dealer_id mismatch");
                assert!(
                    proof.signatures.len()
                        >= N_PARTIES_NON_EQ - (N_PARTIES_NON_EQ - THRESHOLD_NON_EQ),
                    "proof for party {dealer_id} must have quorum signatures"
                );
            }
        }
        KeygenResult::Blamed(blamed) => {
            panic!("expected Complete, got Blamed({blamed:?})");
        }
    }
}

#[test]
fn equivocation_detected_with_nonequiv() {
    let mut sim = non_eq_simulator();
    sim.inject_fault(1, FaultType::Equivocate);

    let result = sim.run().unwrap();
    match result {
        KeygenResult::Blamed(blamed) => assert!(blamed.contains(&1), "party 1 must be blamed"),
        KeygenResult::Complete(_) => panic!("equivocation must not complete successfully"),
    }
}
