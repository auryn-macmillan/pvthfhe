use pvthfhe_keygen::dkg::{DkgCeremony, DkgParams};

#[test]
fn dkg_pop_verify_honest_accepts() {
    let params = DkgParams { n: 3, t: 2, round_timeout: None };
    let mut dkg = DkgCeremony::new(params).expect("DKG new");
    dkg.run().expect("DKG run");

    let identities = dkg.party_identities();
    assert_eq!(identities.len(), 3);
    assert!(identities
        .iter()
        .all(|id| id.party_id >= 1 && id.party_id <= 3));

    assert!(dkg.verify_party_pops());
}

#[test]
fn dkg_run_produces_valid_pops() {
    let params = DkgParams { n: 3, t: 2, round_timeout: None };
    let mut dkg = DkgCeremony::new(params).expect("DKG new");
    dkg.run().expect("DKG run");

    let identities = dkg.party_identities();
    assert_eq!(identities.len(), 3);
    assert!(identities
        .iter()
        .all(|id| id.party_id >= 1 && id.party_id <= 3));

    assert!(dkg.verify_party_pops());
}

#[test]
fn forged_pop_is_rejected() {
    let params = DkgParams { n: 3, t: 2, round_timeout: None };
    let mut dkg = DkgCeremony::new(params).expect("DKG new");
    dkg.run().expect("DKG run");

    let identities = dkg.party_identities();
    let party_1_pk = identities[0].public_key;
    let party_2_pop = &identities[1].pop_proof;

    // party 2's PoP should NOT verify against party 1's key
    assert!(!pvthfhe_nizk::schnorr::schnorr_pop_verify(
        party_1_pk,
        party_2_pop
    ));
}

#[test]
fn empty_ceremony_rejects_pop_verification() {
    let params = DkgParams { n: 3, t: 2, round_timeout: None };
    let dkg = DkgCeremony::new(params).expect("DKG new");
    assert!(!dkg.verify_party_pops());
}
