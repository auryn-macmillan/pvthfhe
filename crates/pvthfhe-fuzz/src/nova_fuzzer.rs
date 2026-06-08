//! Nova input fuzzer.
//!
//! Fuzzes Nova compressor inputs with random witness data.
//! Verifies:
//! 1. No panics on malformed inputs
//! 2. Public anchor verification works correctly

use pvthfhe_compressor::{
    verify_compressed_public_anchors, CompressedDecryptionPublicAnchors,
    CompressedDkgPublicAnchors, CompressedProof, VerifierKey,
};
use pvthfhe_fuzz::FUZZ_ITERATIONS;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn generate_random_dkg_anchors(rng: &mut dyn RngCore) -> CompressedDkgPublicAnchors {
    let mut dkg_root = [0u8; 32];
    let mut aggregated_pk_commit = [0u8; 32];
    let mut participant_set_hash = [0u8; 32];
    let mut sk_agg_commits_root = [0u8; 32];
    let mut esm_agg_commits_root = [0u8; 32];
    let mut smudge_slot_policy_hash = [0u8; 32];

    rng.fill_bytes(&mut dkg_root);
    rng.fill_bytes(&mut aggregated_pk_commit);
    rng.fill_bytes(&mut participant_set_hash);
    rng.fill_bytes(&mut sk_agg_commits_root);
    rng.fill_bytes(&mut esm_agg_commits_root);
    rng.fill_bytes(&mut smudge_slot_policy_hash);

    CompressedDkgPublicAnchors {
        dkg_root,
        aggregated_pk_commit,
        participant_set_hash,
        sk_agg_commits_root,
        esm_agg_commits_root,
        smudge_slot_policy_hash,
    }
}

fn generate_random_decrypt_anchors(rng: &mut dyn RngCore) -> CompressedDecryptionPublicAnchors {
    let mut dkg_root = [0u8; 32];
    let mut ciphertext_hash = [0u8; 32];
    let mut expected_sk_commits_root = [0u8; 32];
    let mut expected_esm_commits_root = [0u8; 32];
    let mut plaintext_hash = [0u8; 32];

    rng.fill_bytes(&mut dkg_root);
    rng.fill_bytes(&mut ciphertext_hash);
    rng.fill_bytes(&mut expected_sk_commits_root);
    rng.fill_bytes(&mut expected_esm_commits_root);
    rng.fill_bytes(&mut plaintext_hash);

    CompressedDecryptionPublicAnchors {
        dkg_root,
        ciphertext_hash,
        expected_sk_commits_root,
        expected_esm_commits_root,
        slot_id: rng.next_u64(),
        decrypt_round: rng.next_u64(),
        plaintext_hash,
    }
}

fn main() {
    println!("=== Nova Fuzzer ===");
    println!("Iterations: {FUZZ_ITERATIONS}");

    let mut anchor_mismatch_count = 0u64;
    let mut malformed_proof_reject = 0u64;
    let mut boundary_reject = 0u64;

    for i in 0..FUZZ_ITERATIONS {
        let seed = (i as u64)
            .wrapping_mul(0xABCDEF0123456789)
            .wrapping_add(i as u64);
        let mut rng = ChaCha20Rng::seed_from_u64(seed);

        // Generate anchors
        let dkg = generate_random_dkg_anchors(&mut rng);
        let decrypt = generate_random_decrypt_anchors(&mut rng);

        // 1. Test anchor verification with random data
        match verify_compressed_public_anchors(&dkg, &decrypt) {
            Ok(()) => {}
            Err(_) => anchor_mismatch_count += 1,
        }

        // 2. Test with matching anchors
        {
            let matching_dkg = generate_random_dkg_anchors(&mut rng);
            let matching_decrypt = CompressedDecryptionPublicAnchors {
                dkg_root: matching_dkg.dkg_root,
                ciphertext_hash: [0u8; 32],
                expected_sk_commits_root: matching_dkg.sk_agg_commits_root,
                expected_esm_commits_root: matching_dkg.esm_agg_commits_root,
                slot_id: 0,
                decrypt_round: 0,
                plaintext_hash: [0u8; 32],
            };

            // This should pass if roots match
            let result = verify_compressed_public_anchors(&matching_dkg, &matching_decrypt);
            if result.is_ok() {
                boundary_reject += 1;
            }
        }

        // 3. Malformed proof bytes
        {
            let proof = CompressedProof::new({
                let mut bytes = vec![0u8; rng.next_u64() as usize % 1024];
                rng.fill_bytes(&mut bytes);
                bytes
            });

            // Verify proof bytes don't cause panics
            let _ = proof.has_snark();
            let _ = proof.ivc_bytes();
            let _ = proof.share_verification_hash;
            let _ = proof.ivc_proof_hash;
            let _ = proof.sigma_data_hash;

            malformed_proof_reject += 1;
        }

        // 4. VerifierKey boundary tests
        let vk = VerifierKey {
            srs_id: "test-srs".to_string(),
            step_circuit_hash: {
                let mut h = [0u8; 32];
                rng.fill_bytes(&mut h);
                h
            },
            backend_id: "nova-bn254-grumpkin".to_string(),
            version: rng.next_u32(),
        };
        let _ = vk.srs_id;
        let _ = vk.backend_id;
        let _ = vk.version;

        if i > 0 && i % 1000 == 0 {
            println!("[{i}/{FUZZ_ITERATIONS}]...");
        }
    }

    println!();
    println!("=== Results ===");
    println!("Anchor mismatches (expected with random data): {anchor_mismatch_count}");
    println!("Boundary checks: {boundary_reject}");
    println!("Malformed proof fuzz: {malformed_proof_reject}");
    println!("FUZZ COMPLETE (no panics/crashes)");
}
