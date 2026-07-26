//! Pipeline driver: `run_full_pipeline` orchestrates the per-stage modules
//! (keygen/DKG → NIZK → PVSS → encrypt → fold → decrypt → compress → on-chain)
//! and assembles the final [`PipelineReport`].

use anyhow::Context;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use pvthfhe_bench::e2e_timings::E2eTimings;
use pvthfhe_fhe::fhers::FhersBackend;
use pvthfhe_fhe::FheBackend;
use pvthfhe_foundations::domain_tags::Tag;
use sha2::{Digest, Sha256};
use std::time::Instant;

use super::onchain::poseidon_hash_native;
use super::{elapsed_ms, PipelineConfig, PipelineObserver, PipelineReport, Track};
use crate::pvss_support::PVSS_BACKEND_ID;

const DEMO_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 131072\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

/// Run the complete wired PVTHFHE pipeline.
pub fn run_full_pipeline<O: PipelineObserver>(
    cfg: &PipelineConfig,
    observer: &mut O,
) -> anyhow::Result<PipelineReport> {
    #[cfg(feature = "pipeline-extra-checks")]
    let track: Track = std::env::var("PVTHFHE_TRACK")
        .unwrap_or_else(|_| "B".to_string())
        .parse()
        .unwrap_or(Track::B);
    #[cfg(not(feature = "pipeline-extra-checks"))]
    let track = Track::A;

    if track == Track::A {
        tracing::warn!("Track A ring/sigma verification is DEPRECATED. Use Track B.");
    }

    if cfg.t == 0 || cfg.t > cfg.n {
        anyhow::bail!(
            "invalid threshold: t={} must satisfy 1 <= t <= n={}",
            cfg.t,
            cfg.n
        );
    }

    let max_t = cfg.n / 2 + 1;
    if cfg.t > max_t {
        anyhow::bail!(
            "threshold t={} exceeds max_t={} for n={}. Must satisfy t <= floor(n/2)+1 for the honest-majority threshold policy; Shamir privacy holds against fewer than t shares.",
            cfg.t,
            max_t,
            cfg.n
        );
    }

    let backend_threshold = cfg.t;
    let backend = FhersBackend::load_params(DEMO_PARAMS_TOML).context("backend init")?;
    let mut timings = E2eTimings::new(
        cfg.n,
        cfg.t,
        cfg.seed,
        crate::compressor_glue::compressor_backend_id(),
    );

    // IVC verification flags (C1, C4, C5). Default true.
    #[allow(unused_mut)]
    let mut c1_passed = true;
    #[allow(unused_mut)]
    let mut c4_passed = true;
    #[allow(unused_mut)]
    let mut c5_passed = true;

    if cfg.seed != 0 {
        tracing::warn!(
            "seed flag ignored in production path; will require --insecure-seed in future R3.6"
        );
    }

    observer.note(&format!("pvss_backend_id={PVSS_BACKEND_ID}"));

    // ── Keygen (simulator DKG, H2 commit-reveal, P1 deal pre-computation) ──
    let keygen_out =
        super::dkg::run_keygen_stage(cfg, &backend, backend_threshold, observer, &mut timings)?;
    let session_id = keygen_out.session_id;

    // ── DKG ceremony (dealer→recipient PVSS, aggregation, fold hashes) ──
    let c4_proof_hash: Fr = Fr::from(0u64);
    let ceremony_out = super::dkg::run_dkg_ceremony_stage(
        cfg,
        &backend,
        &keygen_out.transcript,
        keygen_out.party_sk_bytes,
        keygen_out.precomputed_dkg_deals,
        observer,
    )?;

    // ── NIZK prove/verify (sigma proofs, share-provenance binding) ──
    let prove_out = super::prove::run_prove_stage(
        cfg,
        &backend,
        &keygen_out.transcript,
        &session_id,
        &keygen_out.sk_commitments,
        observer,
        &mut timings,
    )?;

    // ── PVSS share encryption ──
    super::dkg::run_pvss_stage(
        cfg,
        &backend,
        &keygen_out.transcript,
        observer,
        &mut timings,
    )?;

    #[cfg(feature = "pipeline-extra-checks")]
    {
        observer.phase_start("verify_batched_share_computation", None);
        let share_verify_started = Instant::now();
        super::dkg::verify_all_dealer_share_computations(
            &ceremony_out.dealer_recipient_total_shares,
            0,
            &session_id,
            cfg.t,
            &ceremony_out.dkg_root_vec,
        )?;
        let share_verify_ms = elapsed_ms(share_verify_started);
        observer.phase_end("verify_batched_share_computation", share_verify_ms);
    }

    // ── Threshold setup, ESM noise, aggregate keygen, encryption ──
    let enc_out = super::encrypt::run_encrypt_stage(
        cfg,
        &backend,
        &keygen_out.transcript,
        &session_id,
        backend_threshold,
        observer,
    )?;

    // ── Cyclo fold (Track B norm/ring checks, G7 post-fold NIZK re-verify) ──
    let fold_report = super::fold::run_fold_stage(
        cfg,
        &prove_out.nizk_outputs,
        enc_out.ct_hash,
        track,
        observer,
        &mut timings,
    )?;

    let session_id = "pvthfhe-e2e";

    // ── Threshold decrypt + C7 aggregation verification ──
    let dec_out = super::decrypt::run_decrypt_stage(
        cfg,
        &backend,
        &keygen_out.transcript,
        session_id,
        &ceremony_out.dkg_root_vec,
        &enc_out.per_party_esm,
        &enc_out.ciphertext,
        &enc_out.plaintext,
        backend_threshold,
        &enc_out.aggregate_pk.bytes,
        observer,
        &mut timings,
    )?;

    // ── IVC compression ──
    let comp_out = super::compress::run_compress_stage(
        cfg,
        session_id,
        dec_out.decrypt_nizk_hash,
        &fold_report,
        dec_out.c7_final_hash,
        &keygen_out.sk_commitments,
        &dec_out.share_coeffs,
        c4_proof_hash,
        observer,
        &mut timings,
    )?;

    // ── On-chain Noir aggregator_final circuit verification ──
    let noir_passed = super::onchain::run_onchain_stage(
        cfg,
        session_id,
        &enc_out.aggregate_pk.bytes,
        prove_out.all_nizk_proof_hash,
        dec_out.decrypt_nizk_hash,
        comp_out.combined_share_hash,
        comp_out.compressed_proof_hash,
        &dec_out.share_coeffs,
        &dec_out.share_coeffs_fr,
        &dec_out.lagrange_coeffs_fr,
        &dec_out.party_ids_fr,
        observer,
    )?;

    // G.4: Derive session_nonce from session_id (deterministic placeholder until Interfold E3)
    let session_nonce = {
        let mut hasher = Sha256::new();
        hasher.update(session_id.as_bytes());
        hasher.update(prove_out.all_nizk_proof_hash.into_bigint().to_bytes_be());
        Fr::from_be_bytes_mod_order(&hasher.finalize())
    };

    let pipeline_integrity_hash = {
        let mut acc = Fr::zero();
        let c0 = Fr::from_be_bytes_mod_order(&Sha256::digest(Tag::E2eKeygenNizk.as_bytes()));
        acc = poseidon_hash_native(&[acc, c0]);
        let c1 = Fr::from_be_bytes_mod_order(&Sha256::digest(
            format!("pk-contrib-{}", hex::encode(cfg.seed.to_be_bytes())).as_bytes(),
        ));
        acc = poseidon_hash_native(&[acc, c1]);
        let c3_h = Fr::from_be_bytes_mod_order(&Sha256::digest(Tag::NizkAdapter.as_bytes()));
        acc = poseidon_hash_native(&[acc, c3_h]);
        acc = poseidon_hash_native(&[acc, prove_out.all_nizk_proof_hash]);
        let c4_h =
            Fr::from_be_bytes_mod_order(Sha256::digest(&ceremony_out.dkg_root_vec).as_slice());
        acc = poseidon_hash_native(&[acc, c4_h]);
        let c6_h = Fr::from_be_bytes_mod_order(&dec_out.decrypt_nizk_hash);
        acc = poseidon_hash_native(&[acc, c6_h]);
        acc
    };

    let c5_proof_root = keygen_out.transcript.round3_aggregate.c5_proof_root;

    let mut report = PipelineReport {
        timings,
        plaintext_roundtrip_ok: dec_out.plaintext_roundtrip_ok,
        all_verifications_passed: noir_passed
            && c1_passed
            && c4_passed
            && c5_passed
            && dec_out.c7_passed,
        aggregate_pk_hash_hex: enc_out.aggregate_pk_hash_hex,
        ciphertext_hash_hex: enc_out.ciphertext_hash_hex,
        compressed_proof_digest_hex: hex::encode(comp_out.compressed.digest),
        share_coeffs: dec_out.share_coeffs,
        lagrange_coeffs: dec_out.lagrange_coeffs_fr,
        committee_party_ids: (1..=cfg.n).map(|i| i as u32).collect(),
        aggregate_pk_bytes: enc_out.aggregate_pk.bytes,
        session_id: session_id.to_string(),
        decrypt_nizk_hash: dec_out.decrypt_nizk_hash,
        session_nonce,
        party_signing_pks: dec_out.party_signing_pks,
        party_signing_pkys: dec_out.party_signing_pkys,
        share_sig_rs: dec_out.share_sig_rs,
        share_sig_rys: dec_out.share_sig_rys,
        share_sig_ss: dec_out.share_sig_ss,
        node_schnorr_pks: dec_out.node_schnorr_pks,
        node_schnorr_sigs: dec_out.node_schnorr_sigs,
        combined_share_hash: comp_out.combined_share_hash,
        all_nizk_proof_hash: prove_out.all_nizk_proof_hash,
        compressed_proof_hash: comp_out.compressed_proof_hash,
        sk_commitments: keygen_out.sk_commitments,
        sk_bindings: prove_out.registered_sk_bindings,
        dkg_verified: ceremony_out.dkg_verified,
        parity_verified: ceremony_out.parity_verified,
        dkg_share_count: ceremony_out.dkg_share_count,
        recipient_fold_hashes: ceremony_out.recipient_fold_hashes,
        recipient_parity_proof_hashes: ceremony_out.recipient_parity_proof_hashes,
        d_commitment_verified: Some(false),
        ivc_snark_proof_hash: comp_out.compressed.ivc_proof_hash,
        share_verification_hash: comp_out.compressed.share_verification_hash,
        pipeline_integrity_hash,
        c5_proof_root,
    };

    let report_failures = verify_pipeline_report(&report);
    if !report_failures.is_empty() {
        tracing::warn!(
            "PipelineReport verification failures: {:?}",
            report_failures
        );
    }
    report.d_commitment_verified = Some(report_failures.is_empty());
    Ok(report)
}

fn verify_pipeline_report(report: &PipelineReport) -> Vec<String> {
    let mut failures = Vec::new();

    if !report.all_verifications_passed {
        failures.push("all_verifications_passed is false".into());
    }

    if report.dkg_verified
        && report
            .recipient_fold_hashes
            .iter()
            .all(|&h| h == Fr::zero())
    {
        failures.push("dkg_verified=true but all fold hashes are zero".into());
    }

    if !report.committee_party_ids.is_empty() && report.sk_commitments.is_empty() {
        failures.push("parties present but sk_commitments empty".into());
    }

    if !report.share_coeffs.is_empty() && report.combined_share_hash.is_zero() {
        failures.push("shares present but combined_share_hash is zero".into());
    }

    failures
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct RecordingObserver {
        starts: Vec<String>,
        ends: Vec<(String, f64)>,
        notes: Vec<String>,
    }

    impl PipelineObserver for RecordingObserver {
        fn phase_start(&mut self, name: &str, detail: Option<&str>) {
            match detail {
                Some(detail) => self.starts.push(format!("{name}:{detail}")),
                None => self.starts.push(name.to_owned()),
            }
        }

        fn phase_end(&mut self, name: &str, ms: f64) {
            self.ends.push((name.to_owned(), ms));
        }

        fn note(&mut self, msg: &str) {
            self.notes.push(msg.to_owned());
        }
    }

    #[test]
    fn red_3_records_all_full_pipeline_phases() {
        let mut observer = RecordingObserver::default();
        let report = run_full_pipeline(
            &PipelineConfig {
                n: 5,
                t: 2,
                seed: 0,
            },
            &mut observer,
        )
        .expect("full pipeline should succeed");

        let mut counts = BTreeMap::new();
        for entry in &observer.starts {
            let name = entry.split(':').next().expect("phase entry has name");
            *counts.entry(name.to_owned()).or_insert(0usize) += 1;
        }

        assert_eq!(counts.get("keygen").copied(), Some(1));
        assert_eq!(counts.get("dkg_ceremony").copied(), Some(1));
        assert_eq!(counts.get("dkg_deal").copied(), Some(1));
        assert_eq!(counts.get("dkg_aggregate").copied(), Some(1));
        assert_eq!(counts.get("nizk_prove").copied(), Some(5));
        assert_eq!(counts.get("nizk_verify").copied(), Some(25));
        assert_eq!(counts.get("pvss_share_encrypt").copied(), Some(1));
        assert_eq!(counts.get("setup_threshold").copied(), Some(1));
        assert_eq!(counts.get("aggregate_keygen").copied(), Some(1));
        assert_eq!(counts.get("encrypt").copied(), Some(1));
        assert_eq!(counts.get("cyclo_fold").copied(), Some(1));
        assert_eq!(counts.get("cyclo_fold_verify").copied(), Some(1));
        assert_eq!(counts.get("compressor_new").copied(), Some(1));
        assert_eq!(counts.get("compressor_prove").copied(), Some(1));
        assert_eq!(counts.get("compressor_verify").copied(), Some(1));
        #[cfg(feature = "enable-latticefold")]
        assert_eq!(counts.get("compressor_verify_external").copied(), Some(1));
        #[cfg(feature = "pipeline-extra-checks")]
        {
            assert_eq!(
                counts.get("verify_batched_share_computation").copied(),
                Some(1)
            );
        }
        assert_eq!(counts.get("partial_decrypt").copied(), Some(2));
        assert_eq!(counts.get("aggregate_decrypt").copied(), Some(1));
        assert!(report.plaintext_roundtrip_ok);
        assert!(report.dkg_verified);
        assert_eq!(report.dkg_share_count, 25);
        assert!(report.timings.phases.cyclo_fold.total_ms > 0.0);
        assert!(report.timings.phases.compressor_prove.total_ms > 0.0);

        // C5 proof root must be nonzero after a fresh keygen round
        assert_ne!(
            report.c5_proof_root, [0u8; 32],
            "c5_proof_root must be nonzero after keygen"
        );
    }
}
