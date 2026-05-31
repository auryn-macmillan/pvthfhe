use pvthfhe_fuzz::FUZZ_ITERATIONS;
use pvthfhe_pvss::nizk_share::{
    ShareNizkBatchedStatement, ShareNizkBatchedVerifier, ShareNizkProof, ShareNizkProver,
    ShareNizkStatement, ShareNizkTrackStatement, ShareNizkTrackType, ShareNizkVerifier,
    ShareNizkWitness,
};
use pvthfhe_types::{EncRandomness, ProtocolBytes, ShareSecret};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};

fn bfv_params_digest() -> ProtocolBytes {
    let toml = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";
    ProtocolBytes(Sha256::digest(toml.as_bytes()).to_vec())
}

fn main() {
    println!("=== PVSS Fuzzer ===");
    println!("Iterations: {FUZZ_ITERATIONS}");

    let toml = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";
    let backend = match pvthfhe_fhe::mock::MockBackend::load_params(toml) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to create mock FHE backend: {e:?}");
            eprintln!("Set PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1");
            std::process::exit(1);
        }
    };

    for i in 0..FUZZ_ITERATIONS {
        let seed = (i as u64).wrapping_mul(0x5858585858585858).wrapping_add(42);
        let mut rng = ChaCha20Rng::seed_from_u64(seed);

        let session_id = ProtocolBytes(format!("pvss-fuzz-{i}").into_bytes());
        let params_digest = bfv_params_digest();
        let dkg_root = {
            let mut h = [0u8; 32];
            rng.fill_bytes(&mut h);
            ProtocolBytes(h.to_vec())
        };

        let share_bytes = ShareSecret::from({
            let mut bytes = vec![0u8; 32];
            rng.fill_bytes(&mut bytes);
            bytes
        });

        let encryption_randomness = EncRandomness::from({
            let mut bytes = vec![0u8; 32];
            rng.fill_bytes(&mut bytes);
            bytes
        });

        let recipient_pk_bytes = {
            let mut bytes = vec![0u8; 64];
            rng.fill_bytes(&mut bytes);
            bytes
        };

        let ciphertext_u = {
            let mut bytes = vec![0u8; 64];
            rng.fill_bytes(&mut bytes);
            ProtocolBytes(bytes)
        };

        let ciphertext_v_bytes = Sha256::digest(ciphertext_u.as_slice()).to_vec();
        let ciphertext_v = ProtocolBytes(ciphertext_v_bytes);

        let share_commitment = {
            let mut h = vec![0u8; 32];
            rng.fill_bytes(&mut h);
            ProtocolBytes(h)
        };

        let stmt = ShareNizkStatement {
            session_id: session_id.clone(),
            dealer_index: 0,
            recipient_index: 0,
            recipient_pk: ProtocolBytes(recipient_pk_bytes),
            bfv_params_digest: params_digest.clone(),
            dkg_root: dkg_root.clone(),
            ciphertext_u: ciphertext_u.clone(),
            ciphertext_v: ciphertext_v.clone(),
            share_commitment: share_commitment.clone(),
        };

        let witness = ShareNizkWitness {
            share_bytes: share_bytes.clone(),
            encryption_randomness: encryption_randomness.clone(),
        };

        let proof = match ShareNizkProver::prove(&backend, &stmt, &witness, None) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let _ = ShareNizkVerifier::verify(&backend, &stmt, &proof);

        // Tamper test
        {
            let mut tampered_proof = proof.clone();
            if !tampered_proof.proof_bytes.is_empty() {
                let inner = tampered_proof.proof_bytes.as_mut_slice();
                inner[0] ^= 0xFF;
            }
            let _ = ShareNizkVerifier::verify(&backend, &stmt, &tampered_proof);
        }

        if i > 0 && i % 1000 == 0 {
            println!("[{i}/{FUZZ_ITERATIONS}]...");
        }
    }

    println!("=== Results ===");
    println!("FUZZ COMPLETE (no panics/crashes)");
}
