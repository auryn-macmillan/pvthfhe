#![allow(missing_docs, clippy::unwrap_used, clippy::as_conversions)]

use pvthfhe_aggregator::{
    decrypt::{aggregate_decrypt, partial_decrypt, DecryptError, DecryptSharePayload},
    keygen::simulator::{KeygenResult, KeygenSimulator},
};
use pvthfhe_fhe::{mock::MockBackend, types::Ciphertext, FheBackend};
use rand::{rngs::StdRng, SeedableRng};
use sha2::{Digest, Sha256};

mod equivocation;
mod malformed_nizk;
mod replay;
mod rogue_key;
mod tampered_ciphertext;
mod tampered_share;
mod threshold_above;
mod threshold_below;
mod withhold_reveal;

const TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\n";
const N_PARTIES: usize = 4;
const THRESHOLD: usize = 2;

struct DecryptFixture {
    backend: MockBackend,
    ct: Ciphertext,
    shares: Vec<DecryptSharePayload>,
    threshold: usize,
    allowed_parties: Vec<u32>,
    dkg_root: [u8; 32],
    ciphertext_hash: [u8; 32],
    epoch: u64,
    plaintext: Vec<u8>,
}

fn backend_from_seed(_seed: u64) -> MockBackend {
    MockBackend::load_params(TOML).unwrap()
}

fn simulator_from_seed(seed: u64) -> KeygenSimulator {
    KeygenSimulator::new(N_PARTIES, THRESHOLD, backend_from_seed(seed))
}

fn decrypt_fixture(seed: u64) -> DecryptFixture {
    let backend = backend_from_seed(seed);
    let allowed_parties = vec![1, 2, 3];
    let threshold = THRESHOLD;
    let plaintext = format!("adversarial-seed-{seed}").into_bytes();
    let aggregate_pk = aggregate_public_key(&backend, &allowed_parties, seed);
    let mut encrypt_rng = seeded_rng(seed ^ 0xA5A5_A5A5_A5A5_A5A5);
    let ct = backend
        .encrypt(&aggregate_pk, &plaintext, &mut encrypt_rng)
        .unwrap();
    let dkg_root = hash_bytes(&seed.to_be_bytes());
    let ciphertext_hash = hash_bytes(&ct.bytes);
    let epoch = seed;
    let shares = allowed_parties
        .iter()
        .map(|&party_id| {
            let mut share_rng = seeded_rng(seed ^ ((party_id as u64) << 32));
            partial_decrypt(
                &backend,
                &ct,
                party_id,
                &dkg_root,
                &ciphertext_hash,
                epoch,
                &mut share_rng,
            )
            .unwrap()
        })
        .collect();

    DecryptFixture {
        backend,
        ct,
        shares,
        threshold,
        allowed_parties,
        dkg_root,
        ciphertext_hash,
        epoch,
        plaintext,
    }
}

fn aggregate_public_key(
    backend: &MockBackend,
    party_ids: &[u32],
    seed: u64,
) -> pvthfhe_fhe::PublicKey {
    let shares = party_ids
        .iter()
        .map(|&party_id| {
            let mut rng = seeded_rng(seed ^ party_id as u64);
            backend.keygen_share(party_id, &mut rng).unwrap()
        })
        .collect::<Vec<_>>();
    backend.aggregate_keygen(&shares).unwrap()
}

fn seeded_rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn assert_blamed(result: KeygenResult, cheater: u32) {
    match result {
        KeygenResult::Blamed(blamed) => assert!(
            blamed.contains(&cheater),
            "expected blamed list to include party {cheater}, got {blamed:?}"
        ),
        KeygenResult::Complete(_) => {
            unreachable!("expected party {cheater} to be blamed, but keygen completed")
        }
    }
}

fn aggregate_fixture_shares(
    fixture: &DecryptFixture,
    shares: &[DecryptSharePayload],
) -> Result<Vec<u8>, DecryptError> {
    aggregate_decrypt(
        &fixture.backend,
        &fixture.ct,
        shares,
        fixture.threshold,
        &fixture.allowed_parties,
        &fixture.dkg_root,
        &fixture.ciphertext_hash,
        fixture.epoch,
    )
}
