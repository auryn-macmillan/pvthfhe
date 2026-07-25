//! Threshold setup, committed-smudge noise generation, aggregate keygen, and
//! plaintext encryption stage.

use anyhow::Context;
use pvthfhe_aggregator::keygen::types::DkgTranscript;
use pvthfhe_fhe::{fhers::FhersBackend, Ciphertext, FheBackend, KeygenShare, PublicKey};
use pvthfhe_foundations::rng::OsRng;
use pvthfhe_foundations::types::ProtocolBytes;
use pvthfhe_pvss::nizk_decrypt::derive_party_binding;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Instant;

use super::{elapsed_ms, sha256_bytes, PipelineConfig, PipelineObserver};

/// Outputs of the encryption setup stage.
pub(crate) struct EncryptStageOutput {
    pub(crate) per_party_esm: HashMap<u32, (Vec<u8>, u64, u64)>,
    pub(crate) aggregate_pk: PublicKey,
    pub(crate) plaintext: Vec<u8>,
    pub(crate) ciphertext: Ciphertext,
    pub(crate) ct_hash: [u8; 32],
    pub(crate) aggregate_pk_hash_hex: String,
    pub(crate) ciphertext_hash_hex: String,
}

/// Run threshold setup, ESM noise generation, aggregate keygen, and encryption.
pub(crate) fn run_encrypt_stage<O: PipelineObserver>(
    cfg: &PipelineConfig,
    backend: &FhersBackend,
    transcript: &DkgTranscript,
    session_id: &str,
    backend_threshold: usize,
    observer: &mut O,
) -> anyhow::Result<EncryptStageOutput> {
    observer.phase_start(
        "setup_threshold",
        Some(&format!("backend_threshold={backend_threshold}")),
    );
    let setup_started = Instant::now();
    let session_seed: [u8; 32] = Sha256::digest(session_id.as_bytes()).into();
    backend
        .setup_threshold(cfg.n, backend_threshold, session_seed)
        .context("setup_threshold")?;
    observer.phase_end("setup_threshold", elapsed_ms(setup_started));

    // Generate committed smudging noise per party for CommittedSmudge mode (A.1/A.2).
    observer.phase_start("esm_noise_gen", None);
    let esm_noise_started = Instant::now();
    let mut per_party_esm: HashMap<u32, (Vec<u8>, u64, u64)> = HashMap::new();
    for party_index in 0..cfg.n {
        let party_id = u32::try_from(party_index + 1).context("party id conversion")?;
        let esm_bytes = backend
            .generate_deterministic_esm_noise_for_party(party_id, cfg.seed)
            .context("generate esm noise")?;
        let message = &transcript.round1_messages[party_index];
        let party_pk = backend
            .aggregate_keygen(&[KeygenShare {
                party_id,
                bytes: ProtocolBytes(message.pk_i.bytes.clone()),
            }])
            .context("derive party pk for esm")?
            .bytes;
        let sk_agg_share = derive_party_binding(&party_pk);
        let esm_agg_share = derive_party_binding(&esm_bytes);
        per_party_esm.insert(party_id, (esm_bytes, sk_agg_share, esm_agg_share));
    }
    observer.note(&format!("committed_esm_parties={}", per_party_esm.len()));
    observer.phase_end("esm_noise_gen", elapsed_ms(esm_noise_started));

    let aggregate_pk = transcript.round3_aggregate.aggregate_pk.clone();
    observer.phase_start("aggregate_keygen", None);
    let aggregate_keygen_started = Instant::now();
    let aggregate_keygen_shares = transcript
        .round1_messages
        .iter()
        .map(|message| pvthfhe_fhe::KeygenShare {
            party_id: message.party_id,
            bytes: ProtocolBytes(message.pk_i.bytes.clone()),
        })
        .collect::<Vec<_>>();
    let aggregate_key = backend
        .aggregate_keygen(&aggregate_keygen_shares)
        .context("aggregate_keygen")?;
    if aggregate_pk.bytes != aggregate_key.bytes {
        anyhow::bail!("DKG aggregate key mismatch");
    }
    observer.phase_end("aggregate_keygen", elapsed_ms(aggregate_keygen_started));

    let plaintext = 0xB10C_u64.to_le_bytes().to_vec();
    let mut encrypt_rng = OsRng;
    observer.phase_start("encrypt", None);
    let encrypt_started = Instant::now();
    let ciphertext = backend
        .encrypt(&aggregate_pk, &plaintext, &mut encrypt_rng)
        .context("encrypt")?;
    observer.phase_end("encrypt", elapsed_ms(encrypt_started));
    let ct_hash = sha256_bytes(&ciphertext.bytes);
    let aggregate_pk_hash_hex = hex::encode(sha256_bytes(&aggregate_pk.bytes));
    let ciphertext_hash_hex = hex::encode(ct_hash);

    Ok(EncryptStageOutput {
        per_party_esm,
        aggregate_pk,
        plaintext,
        ciphertext,
        ct_hash,
        aggregate_pk_hash_hex,
        ciphertext_hash_hex,
    })
}
