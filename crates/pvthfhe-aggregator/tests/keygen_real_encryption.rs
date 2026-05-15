//! Integration tests: keygen real encryption + NIZK verification (R4).
//!
//! Verifies that the KeygenSimulator produces real BFV ciphertexts and real
//! Cyclo NIZK proofs, not the hardcoded 2-byte stubs.

use pvthfhe_aggregator::keygen::simulator::{KeygenResult, KeygenSimulator};
use pvthfhe_fhe::fhers::FhersBackend;
use pvthfhe_fhe::FheBackend;
use pvthfhe_nizk::adapter::CycloNizkAdapter;
use pvthfhe_nizk::{NizkAdapter, NizkProof, NizkStatement};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

const TEST_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

fn must<T, E: core::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{context}: {error:?}"),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Derive party_id from 0-based index (mimics `party_id_from_index`).
fn party_id(index: usize) -> u32 {
    u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX)
}

/// Hash bytes with SHA-256.
fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Compute `session_id` the same way the simulator does.
fn compute_session_id(n_parties: usize, threshold: usize) -> [u8; 32] {
    let tag = b"pvthfhe/keygen-simulator/session/v1";

    // participant_set_hash
    let mut psh_data = Vec::with_capacity(n_parties * 4);
    for i in 0..n_parties {
        psh_data.extend_from_slice(&party_id(i).to_be_bytes());
    }
    let psh = hash_bytes(&psh_data);

    let mut data = Vec::with_capacity(72);
    data.extend_from_slice(tag);
    data.extend_from_slice(&psh);
    data.extend_from_slice(&(threshold as u32).to_be_bytes());
    hash_bytes(&data)
}

/// Derive the keygen share for a (session_id, party_id) pair using a fresh
/// backend with the same parameters.  This produces the same bytes that the
/// simulator would encrypt.
fn derive_share(
    backend: &FhersBackend,
    session_id: &[u8; 32],
    pid: u32,
) -> pvthfhe_fhe::KeygenShare {
    let mut hasher = Sha256::new();
    hasher.update(b"pvthfhe-sim-keygen-v1");
    hasher.update(session_id);
    hasher.update(&pid.to_be_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    let mut rng = ChaCha8Rng::from_seed(seed); // allow-seeded-rng: deterministic simulator

    if backend.supports_session_scoped_keygen() {
        backend
            .keygen_share_with_session(session_id, pid, &mut rng)
            .expect("fresh backend keygen_share_with_session")
    } else {
        backend
            .keygen_share(pid, &mut rng)
            .expect("fresh backend keygen_share")
    }
}

/// Deserialize a NIZK proof bundle (produced by `serialize_nizk_bundle`).
///
/// Returns individual proof byte vectors.
fn deserialize_nizk_bundle(bundle: &[u8]) -> Vec<Vec<u8>> {
    if bundle.len() < 2 {
        return vec![];
    }
    let count = u16::from_be_bytes([bundle[0], bundle[1]]) as usize;
    let mut proofs = Vec::with_capacity(count);
    let mut offset = 2;
    for _ in 0..count {
        if offset + 4 > bundle.len() {
            break;
        }
        let len = u32::from_be_bytes([
            bundle[offset],
            bundle[offset + 1],
            bundle[offset + 2],
            bundle[offset + 3],
        ]) as usize;
        offset += 4;
        if offset + len > bundle.len() {
            break;
        }
        proofs.push(bundle[offset..offset + len].to_vec());
        offset += len;
    }
    proofs
}

/// Compute the pvss_commitment used in NIZK statements (same as
/// `prove_keygen_nizk`).
fn compute_pvss_commitment(
    session_id: &[u8; 32],
    dealer_id: u32,
    plaintext: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(session_id);
    h.update(&dealer_id.to_be_bytes());
    h.update(plaintext);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Build a NizkStatement matching what `prove_keygen_nizk` produces.
fn build_nizk_statement(
    ciphertext_bytes: Vec<u8>,
    pvss_commitment: [u8; 32],
    session_str: String,
    dealer_id: u32,
) -> pvthfhe_nizk::NizkStatement {
    let participant_id = u16::try_from(dealer_id).expect("dealer_id fits u16");
    pvthfhe_nizk::NizkStatement {
        ciphertext_bytes,
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment,
        params: (
            65_537,
            pvthfhe_nizk::sigma::RLWE_N,
            pvthfhe_nizk::sigma::SIGMA_B_E as u64,
        ),
        session_id: session_str,
        participant_id,
        epoch: 0,
    }
}

// ---------------------------------------------------------------------------
// Test 1: keygen_encrypt_not_stub
// ---------------------------------------------------------------------------

/// Encrypted shares MUST be real BFV ciphertexts, not the 2-byte stubs
/// [0x11, 0x22].  Real BFV ciphertexts for n=8192 and 3 RNS moduli should be
/// several hundred kilobytes.
#[test]
fn keygen_encrypt_not_stub() {
    let backend = must(FhersBackend::load_params(TEST_PARAMS_TOML), "load backend");
    let mut sim = KeygenSimulator::new_with_backend(4, 1, backend).unwrap();
    let result = must(sim.run(), "run keygen");

    let transcript = match result {
        KeygenResult::Complete(t) => t,
        KeygenResult::Blamed(b) => panic!("unexpected blame: {b:?}"),
    };

    // Every round-1 message (from a non-blamed party) must have encrypted_shares
    // that are real ciphertexts, not stubs.
    for msg in &transcript.round1_messages {
        for (&recipient_id, ct_bytes) in &msg.encrypted_shares {
            // Stub ciphertext is 2 bytes ([0x11, 0x22]).
            // Real ciphertext for n=8192, 3 moduli should be >> 100 bytes.
            assert!(
                ct_bytes.len() > 100,
                "party {} → recipient {}: encrypted_share is {} bytes (stub?)",
                msg.party_id,
                recipient_id,
                ct_bytes.len(),
            );
            // It must NOT be the exact 2-byte stub.
            assert_ne!(
                ct_bytes.as_slice(),
                &[0x11, 0x22],
                "party {} → recipient {}: encrypted_share is the hardcoded stub",
                msg.party_id,
                recipient_id,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Test 2: keygen_nizk_not_empty
// ---------------------------------------------------------------------------

/// The NIZK field in each Round1Message MUST be populated (not the fallback
/// [0x00, 0x01]) when encryption succeeds.
#[test]
fn keygen_nizk_not_empty() {
    let backend = must(FhersBackend::load_params(TEST_PARAMS_TOML), "load backend");
    let mut sim = KeygenSimulator::new_with_backend(4, 1, backend).unwrap();
    let result = must(sim.run(), "run keygen");

    let transcript = match result {
        KeygenResult::Complete(t) => t,
        KeygenResult::Blamed(b) => panic!("unexpected blame: {b:?}"),
    };

    for msg in &transcript.round1_messages {
        // The NIZK must NOT be the empty fallback.
        assert_ne!(
            msg.nizk.as_slice(),
            &[0x00, 0x01],
            "party {}: NIZK is the empty fallback",
            msg.party_id,
        );
        // It must contain at least the bundle header (2-byte count).
        assert!(
            msg.nizk.len() >= 2,
            "party {}: NIZK field too short ({})",
            msg.party_id,
            msg.nizk.len(),
        );
        // Deserialize the bundle and verify each proof has non-trivial bytes.
        let proofs = deserialize_nizk_bundle(&msg.nizk);
        assert!(
            !proofs.is_empty(),
            "party {}: NIZK bundle contains zero proofs",
            msg.party_id,
        );
        for (i, proof) in proofs.iter().enumerate() {
            assert!(
                proof.len() > 2,
                "party {} proof {}: proof bytes too short ({})",
                msg.party_id,
                i,
                proof.len(),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Test 3: keygen_nizk_verify_passes
// ---------------------------------------------------------------------------

/// Full verification: deserialize each NIZK proof, reconstruct the statement,
/// and call `CycloNizkAdapter::verify`.  This exercises the real NIZK path
/// end-to-end.
#[test]
fn keygen_nizk_verify_passes() {
    let n_parties: usize = 4;
    let threshold: usize = 1;

    let backend = must(FhersBackend::load_params(TEST_PARAMS_TOML), "load backend");
    let mut sim = KeygenSimulator::new_with_backend(n_parties, threshold, backend).unwrap();
    let result = must(sim.run(), "run keygen");

    let transcript = match result {
        KeygenResult::Complete(t) => t,
        KeygenResult::Blamed(b) => panic!("unexpected blame: {b:?}"),
    };

    let session_id = compute_session_id(n_parties, threshold);
    let session_str = hex::encode(session_id);

    // Fresh backend for witness derivation.
    let witness_backend = must(FhersBackend::load_params(TEST_PARAMS_TOML), "load witness backend");

    let adapter = CycloNizkAdapter;

    for msg in &transcript.round1_messages {
        let dealer_id = msg.party_id;
        let proofs = deserialize_nizk_bundle(&msg.nizk);

        // Collect (recipient_id, ct_bytes) in a stable order matching
        // the order the simulator inserted into `encrypted_shares` and
        // `nizk_proofs`.
        let mut pairs: Vec<(u32, &Vec<u8>)> = msg
            .encrypted_shares
            .iter()
            .map(|(&rid, ct)| (rid, ct))
            .collect();
        pairs.sort_by_key(|(rid, _)| *rid);

        assert_eq!(
            proofs.len(),
            pairs.len(),
            "party {}: NIZK proof count ({}) != encrypted share count ({})",
            dealer_id,
            proofs.len(),
            pairs.len(),
        );

        for (recipient_id, ct_bytes) in &pairs {
            // Derive the plaintext (same as what the simulator encrypted).
            let share = derive_share(&witness_backend, &session_id, dealer_id);
            let plaintext = share.bytes.0.clone();

            let pvss_commitment =
                compute_pvss_commitment(&session_id, dealer_id, &plaintext);

            let statement = build_nizk_statement(
                (*ct_bytes).clone(),
                pvss_commitment,
                session_str.clone(),
                dealer_id,
            );

            // Find the proof for this recipient.  The proofs are in the same
            // order as the sorted pairs (same iteration order over
            // encrypted_shares).
            let pair_idx = pairs
                .iter()
                .position(|(rid, _)| *rid == *recipient_id)
                .expect("recipient in pairs");
            let proof_bytes = &proofs[pair_idx];

            let proof = NizkProof {
                backend_id: "cyclo-ajtai-d2-conditional".to_string(),
                proof_bytes: proof_bytes.clone(),
            };

            let verify_result = adapter.verify(&statement, &proof);

            match verify_result {
                Ok(()) => {} // success
                Err(e) => {
                    panic!(
                        "NIZK verify failed: dealer={dealer_id} → recipient={recipient_id}: {e:?}"
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Test 4: keygen_encrypt_structure
// ---------------------------------------------------------------------------

/// Verify internal consistency: each round-1 message must have the same number
/// of encrypted shares as there are other parties, and each NIZK field must
/// deserialize to the expected number of proofs.
#[test]
fn keygen_encrypt_structure() {
    let n_parties: usize = 6;
    let threshold: usize = 2;

    let backend = must(FhersBackend::load_params(TEST_PARAMS_TOML), "load backend");
    let mut sim = KeygenSimulator::new_with_backend(n_parties, threshold, backend).unwrap();
    let result = must(sim.run(), "run keygen");

    let transcript = match result {
        KeygenResult::Complete(t) => t,
        KeygenResult::Blamed(b) => panic!("unexpected blame: {b:?}"),
    };

    for msg in &transcript.round1_messages {
        // Each party encrypts shares for every OTHER party.
        let expected_shares = n_parties - 1;
        assert_eq!(
            msg.encrypted_shares.len(),
            expected_shares,
            "party {}: expected {} encrypted shares, got {}",
            msg.party_id,
            expected_shares,
            msg.encrypted_shares.len(),
        );

        // The NIZK bundle should contain one proof per encrypted share.
        let proofs = deserialize_nizk_bundle(&msg.nizk);
        assert_eq!(
            proofs.len(),
            expected_shares,
            "party {}: expected {} NIZK proofs, got {}",
            msg.party_id,
            expected_shares,
            proofs.len(),
        );

        // No encrypted share should be empty (real BFV ciphertexts are non-trivial).
        for (&recipient_id, ct_bytes) in &msg.encrypted_shares {
            assert!(
                !ct_bytes.is_empty(),
                "party {} → recipient {}: encrypted share is empty",
                msg.party_id,
                recipient_id,
            );
        }
    }
}
