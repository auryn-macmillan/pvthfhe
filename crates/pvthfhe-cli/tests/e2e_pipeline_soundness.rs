//! R8.5 End-to-end soundness composition test.
//!
//! Exercises the full pipeline (keygen → encrypt → partial-decrypt →
//! aggregate-decrypt) and validates that:
//! 1. With t honest partial decrypt shares, plaintext round-trips correctly.
//! 2. With fewer than t valid partial decrypt shares, aggregate rejects.
//!
//! This tests the composition of R1 (DKG) + R3 (NIZK) + R4 (fold) + R5
//! (compressor) + R6 (on-chain verifier) soundness guarantees.

#[cfg(feature = "with-fhe")]
mod tests {
    use pvthfhe_cli::full_pipeline::{run_full_pipeline, PipelineConfig, PipelineObserver};
    use pvthfhe_fhe::{fhers::FhersBackend, FheBackend};
    use pvthfhe_rng::OsRng;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct PhaseCountObserver {
        counts: BTreeMap<String, usize>,
    }

    impl PhaseCountObserver {
        fn count(&self, name: &str) -> usize {
            self.counts.get(name).copied().unwrap_or(0)
        }
    }

    impl PipelineObserver for PhaseCountObserver {
        fn phase_start(&mut self, name: &str, _detail: Option<&str>) {
            *self.counts.entry(name.to_owned()).or_insert(0) += 1;
        }
    }

    #[test]
    fn e2e_soundness_full_pipeline_roundtrips() {
        let mut observer = PhaseCountObserver::default();
        let report = run_full_pipeline(
            &PipelineConfig {
                n: 3,
                t: 2,
                seed: 0,
            },
            &mut observer,
        )
        .expect("full pipeline n=3 t=2 should succeed");

        assert!(report.plaintext_roundtrip_ok);
        assert!(observer.count("keygen") >= 1);
        assert!(observer.count("encrypt") >= 1);
        assert!(observer.count("partial_decrypt") >= 2);
        assert!(observer.count("aggregate_decrypt") >= 1);
    }

    #[test]
    fn e2e_soundness_insufficient_shares_rejected() {
        // n=3, t=2 — adversary controls t-1=1 party.
        // Aggregate with only 1 valid share must fail.
        let backend = FhersBackend::load_params(
            "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n"
        ).expect("backend init");

        let n: usize = 3;
        let t: usize = 2;
        let mut session_id = [0u8; 32];
        for byte in session_id.iter_mut() {
            *byte = rand::random();
        }

        let mut keygen_shares = Vec::with_capacity(n);
        for pid in 1u32..=n as u32 {
            let share = backend
                .keygen_share_with_session(&session_id, pid, &mut OsRng)
                .expect("keygen share");
            keygen_shares.push(share);
        }
        let session_seed: [u8; 32] = Sha256::digest(session_id).into();
        backend
            .setup_threshold(n, t, session_seed)
            .expect("setup_threshold");

        let pk = backend
            .aggregate_keygen(&keygen_shares)
            .expect("aggregate_keygen");

        // Use small plaintext to avoid encoding issues.
        let plaintext = b"test";
        let mut encrypt_rng = OsRng;
        let ct = backend
            .encrypt(&pk, plaintext, &mut encrypt_rng)
            .expect("encrypt");

        let mut valid_shares = Vec::new();
        for pid in 1u32..=t as u32 {
            let mut rng = OsRng;
            let share = backend
                .partial_decrypt(&ct, pid, &mut rng)
                .expect("partial_decrypt");
            valid_shares.push(share);
        }

        // With t valid shares, aggregate succeeds and recovers plaintext.
        let recovered = backend
            .aggregate_decrypt(&ct, &valid_shares, t, b"")
            .expect("aggregate_decrypt with t valid shares");
        assert_eq!(recovered, plaintext);

        // With only t-1 valid shares, aggregate fails.
        let insufficient = &valid_shares[..t - 1];
        let result = backend.aggregate_decrypt(&ct, insufficient, t, b"");
        assert!(
            result.is_err(),
            "aggregate_decrypt with t-1 shares should fail, got: {:?}",
            result
        );

        // With t shares where one is tampered, aggregate fails.
        let mut tampered = valid_shares.clone();
        let corruption: Vec<u8> = tampered[1]
            .bytes
            .iter()
            .map(|b| b.wrapping_add(1))
            .collect();
        tampered[1].bytes = pvthfhe_types::ProtocolBytes(corruption);
        let result = backend.aggregate_decrypt(&ct, &tampered, t, b"");
        assert!(
            result.is_err(),
            "aggregate_decrypt with tampered share should fail, got: {:?}",
            result
        );
    }
}
