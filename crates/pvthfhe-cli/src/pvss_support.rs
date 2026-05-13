use anyhow::Context;
use pvthfhe_aggregator::keygen::types::DkgTranscript;
use pvthfhe_fhe::{fhers::FhersBackend, FheBackend, KeygenShare};
use pvthfhe_pvss::{
    nizk_decrypt::{derive_party_binding, DecryptNizkWitness},
    nizk_share::ShareNizkProof,
    DecryptedShare, LatticePvssBfvAdapter, PvssAdapter, PvssContext,
};
use pvthfhe_rng::OsRng;
use pvthfhe_types::{ProtocolBytes, Secret};
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Instant;

/// Stable backend identifier for the default lattice PVSS adapter.
pub const PVSS_BACKEND_ID: &str = "lattice-pvss-bfv-d2";

/// Timing artifacts collected from one lattice-PVSS execution.
#[derive(Debug, Clone)]
pub struct PvssRunArtifacts {
    /// Total share-dealing time in milliseconds.
    pub deal_ms: u128,
    /// Total share-verification time in milliseconds.
    pub verify_ms: u128,
    /// Total recovery time in milliseconds.
    pub recover_ms: u128,
    /// Share-encryption proof cost in milliseconds.
    pub share_encryption_proof_ms: u128,
    /// Total decrypt-side proof generation cost in milliseconds.
    pub decrypt_prove_total_ms: f64,
    /// Per-instance decrypt-side proof generation costs in milliseconds.
    pub decrypt_prove_per_instance_ms: Vec<f64>,
}

/// Runs the default lattice-PVSS flow over the demo/e2e transcript.
pub fn run_lattice_pvss(
    backend: &FhersBackend,
    transcript: &DkgTranscript,
    threshold: usize,
    session_label: &str,
    seed: u64,
) -> anyhow::Result<PvssRunArtifacts> {
    let adapter =
        LatticePvssBfvAdapter::new().map_err(|err| anyhow::anyhow!("pvss init: {err}"))?;
    let session_id = pvss_session_id(session_label, transcript, seed);
    let dealer_index = pvthfhe_pvss::derive_dealer_index(&session_id);
    let ctx = PvssContext {
        n: transcript.participant_set.len(),
        t: threshold,
        session_id: session_id.clone(),
        epoch: 0,
        dkg_root: transcript.dkg_root.to_vec(),
        dealer_index,
    };
    let recipient_pks = derive_recipient_public_keys(backend, transcript)?;
    let secret = derive_secret(transcript);

    let deal_started = Instant::now();
    let encrypted = adapter
        .deal(&secret, &recipient_pks, &ctx)
        .map_err(|err| anyhow::anyhow!("pvss deal: {err}"))?;
    let deal_ms = elapsed_ms(deal_started.elapsed());

    let verify_started = Instant::now();
    adapter
        .verify_shares(&encrypted, &ctx)
        .map_err(|err| anyhow::anyhow!("pvss verify_shares: {err}"))?;
    let verify_ms = elapsed_ms(verify_started.elapsed());

    // Generate esm noise per party for CommittedSmudge mode (A.2)
    let mut per_party_esm: HashMap<u32, (Vec<u8>, u64, u64)> = HashMap::new();
    for i in 0..ctx.n {
        let party_id = u32::try_from(i + 1).context("party index to id")?;
        let esm_bytes = backend
            .generate_deterministic_esm_noise_for_party(party_id, seed)
            .context("generate esm noise for pvss")?;
        let party_pk = &recipient_pks[i];
        let sk_agg_share = derive_party_binding(party_pk);
        let esm_agg_share = derive_party_binding(&esm_bytes);
        per_party_esm.insert(party_id, (esm_bytes, sk_agg_share, esm_agg_share));
    }

    let mut decrypt_prove_per_instance_ms = Vec::with_capacity(threshold);
    let decrypted_shares = encrypted
        .ciphertexts
        .iter()
        .zip(encrypted.proofs.iter())
        .zip(encrypted.share_bytes.iter())
        .take(threshold)
        .enumerate()
        .map(|(index, ((ciphertext_u, proof_bytes), share_bytes))| {
            let proof = ShareNizkProof::from_bytes(proof_bytes.clone())
                .map_err(|err| anyhow::anyhow!("pvss share proof decode {index}: {err}"))?;
            let opened = proof
                .decode()
                .map_err(|err| anyhow::anyhow!("pvss opened share proof {index}: {err}"))?;
            let decrypt_prove_started = Instant::now();
            let party_id = u32::try_from(index + 1).context("party index to id")?;
            let secret_key_bytes = backend
                .party_secret_key_bytes(party_id)
                .with_context(|| format!("get secret key for party {party_id}"))?;
            let mut decryption_noise = vec![0u8; secret_key_bytes.len()];
            OsRng.fill_bytes(&mut decryption_noise);
            let (committed_esm, sk_agg_share, esm_agg_share) = per_party_esm
                .get(&party_id)
                .map(|(eb, sk, esm)| (Some(eb.clone()), Some(*sk), Some(*esm)))
                .unwrap_or((None, None, None));
            let decrypted_share = adapter
                .prove_decrypted_share(
                    ciphertext_u,
                    opened.statement.recipient_pk.as_slice(),
                    index,
                    share_bytes.clone(),
                    &DecryptNizkWitness {
                        secret_key_bytes: Secret::new(secret_key_bytes),
                        decryption_noise: Secret::new(decryption_noise),
                        sk_agg_share,
                        esm_agg_share,
                        esm_noise_poly_bytes: committed_esm.clone(),
                    },
                    &ctx,
                    committed_esm,
                    sk_agg_share,
                )
                .map_err(|err| anyhow::anyhow!("pvss prove_decrypted_share {index}: {err}"))?;
            decrypt_prove_per_instance_ms
                .push(decrypt_prove_started.elapsed().as_secs_f64() * 1_000.0);
            Ok(decrypted_share)
        })
        .collect::<anyhow::Result<Vec<DecryptedShare>>>()?;

    let recover_started = Instant::now();
    let recovered = adapter
        .recover(&decrypted_shares, &ctx)
        .map_err(|err| anyhow::anyhow!("pvss recover: {err}"))?;
    let recover_ms = elapsed_ms(recover_started.elapsed());

    anyhow::ensure!(recovered == secret, "pvss recovered secret mismatch");

    Ok(PvssRunArtifacts {
        deal_ms,
        verify_ms,
        recover_ms,
        share_encryption_proof_ms: deal_ms,
        decrypt_prove_total_ms: decrypt_prove_per_instance_ms.iter().sum(),
        decrypt_prove_per_instance_ms,
    })
}

fn derive_recipient_public_keys<B: FheBackend>(
    backend: &B,
    transcript: &DkgTranscript,
) -> anyhow::Result<Vec<Vec<u8>>> {
    transcript
        .round1_messages
        .iter()
        .map(|message| {
            backend
                .aggregate_keygen(&[KeygenShare {
                    party_id: message.party_id,
                    bytes: ProtocolBytes(message.pk_i.bytes.clone()),
                }])
                .map(|pk| pk.bytes)
                .with_context(|| format!("derive recipient pk for party {}", message.party_id))
        })
        .collect()
}

fn derive_secret(transcript: &DkgTranscript) -> Vec<u8> {
    sha256_bytes(&transcript.round3_aggregate.aggregate_pk.bytes).to_vec()
}

fn pvss_session_id(session_label: &str, transcript: &DkgTranscript, seed: u64) -> Vec<u8> {
    let mut binding = Vec::new();
    binding.extend_from_slice(session_label.as_bytes());
    binding.extend_from_slice(&seed.to_be_bytes());
    binding.extend_from_slice(&transcript.round3_aggregate.participant_set_hash);
    sha256_bytes(&binding).to_vec()
}

/// Converts a duration into a non-zero millisecond count.
pub fn elapsed_ms(duration: std::time::Duration) -> u128 {
    duration.as_millis().max(1)
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
