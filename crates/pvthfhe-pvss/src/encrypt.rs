use std::sync::Arc;

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, PrimeField};
use pvthfhe_fhe::{error::FheError, fhers::FhersBackend, types::PublicKey, FheBackend};
use pvthfhe_rng::OsRng;
use pvthfhe_types::{EncRandomness, ProtocolBytes, ShareSecret};
use rand_core::{RngCore, SeedableRng};

use crate::dkg_aggregation::{compute_esm_aggregate_commitment, compute_sk_aggregate_commitment};
use crate::nizk_decrypt::{
    compute_decrypt_ciphertext_hash, DecryptNizkMode, DecryptNizkProof, DecryptNizkProver,
    DecryptNizkStatement, DecryptNizkVerifier, DecryptNizkWitness,
};
use crate::nizk_share::{
    canonical_bfv_params_digest, compute_ciphertext_v, compute_share_commitment, ShareNizkProof,
    ShareNizkProver, ShareNizkStatement, ShareNizkVerifier, ShareNizkWitness,
};
use crate::shamir;
use crate::{DecryptedShare, EncryptedShares, PvssAdapter, PvssContext, PvssError};

const BACKEND_ID: &str = "lattice-pvss-bfv-d2";
const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

/// Maximum bytes that fit losslessly into a single BN254 scalar field element.
/// BN254 `Fr` modulus ≈ 2^254, so 31 bytes (248 bits) always fit below the
/// modulus. The caller (`deal`) chunks larger secrets into 31-byte pieces.
const FR_CHUNK_BYTES: usize = 31;

/// Number of bytes in the serialized representation of one `Fr` element.
/// `BigInt<4>` → 4 × u64 = 32 bytes, fixed width by construction.
const FR_SERIALIZED_LEN: usize = 32;

/// Bytes of length prefix prepended to serialized share payloads so that
/// `recover` can reconstruct the original secret byte-length.
const LENGTH_PREFIX_LEN: usize = 4;

/// Sanity cap on the number of parties (prevents memory exhaustion from
/// accidentally huge `n` values; the BN254 scalar field supports far more).
const MAX_PARTIES: usize = 65535;

/// Per-recipient BFV-backed PVSS adapter.
#[derive(Clone)]
pub struct LatticePvssBfvAdapter {
    backend: Arc<dyn FheBackend>,
}

/// Caller-selected committed-smudge slot use bound into a decryption proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommittedSmudgeUse {
    /// One-based committed smudging slot identifier.
    pub slot_id: u16,
    /// Decryption round bound to this committed slot use.
    pub decrypt_round: u64,
}

impl core::fmt::Debug for LatticePvssBfvAdapter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LatticePvssBfvAdapter")
            .field("backend_id", &BACKEND_ID)
            .finish()
    }
}

impl Default for LatticePvssBfvAdapter {
    fn default() -> Self {
        Self::new().expect("canonical BFV params must load")
    }
}

impl LatticePvssBfvAdapter {
    /// Construct the adapter with the locked real BFV backend.
    pub fn new() -> Result<Self, PvssError> {
        let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).map_err(map_fhe_error)?;
        Ok(Self::new_with_backend(backend))
    }

    /// Construct the adapter with an injected backend for tests.
    pub fn new_with_backend<B>(backend: B) -> Self
    where
        B: FheBackend + 'static,
    {
        Self {
            backend: Arc::new(backend),
        }
    }

    /// Wrap a decrypted share with a deterministic decrypt-side proof.
    ///
    /// When `committed_esm_noise_bytes` and `committed_smudge_use` are both
    /// `Some`, `sk_agg_share` is `Some`, and `esm_agg_share` is available in
    /// the witness, the proof uses `CommittedSmudge` mode. Otherwise the
    /// legacy local-smudge path is used, but still requires an explicit
    /// DKG-committed `sk_agg_share`.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_decrypted_share(
        &self,
        ciphertext_u: &[u8],
        party_pk: &[u8],
        party_index: usize,
        decrypted_share_bytes: Vec<u8>,
        witness: &DecryptNizkWitness,
        ctx: &PvssContext,
        committed_esm_noise_bytes: Option<Vec<u8>>,
        committed_smudge_use: Option<CommittedSmudgeUse>,
        sk_agg_share: Option<u64>,
    ) -> Result<DecryptedShare, PvssError> {
        let dkg_root = share_proof_dkg_root(ctx)?;

        let ciphertext_v = compute_ciphertext_v(ciphertext_u).to_vec();
        let effective_sk_share = sk_agg_share.or(witness.sk_agg_share);
        let effective_esm_share = witness.esm_agg_share;
        let mode = match (committed_esm_noise_bytes, committed_smudge_use) {
            (Some(_), Some(committed_use)) => {
                if committed_use.slot_id == 0 {
                    return Err(PvssError::InvalidShare);
                }
                let sk_val = effective_sk_share.ok_or(PvssError::InvalidShare)?;
                let esm_val = effective_esm_share.ok_or(PvssError::InvalidShare)?;
                let ciphertext_hash = compute_decrypt_ciphertext_hash(ciphertext_u, &ciphertext_v);
                let recipient_id =
                    u16::try_from(party_index).map_err(|_| PvssError::InvalidShare)?;
                let accepted_participant_ids: Vec<u16> = (1..=u16::try_from(ctx.n)
                    .map_err(|_| PvssError::BackendError("n too large for u16".to_string()))?)
                    .collect();
                let sk_agg_commit = compute_sk_aggregate_commitment(
                    &ctx.session_id,
                    &dkg_root,
                    recipient_id,
                    &accepted_participant_ids,
                    ark_bn254::Fr::from(sk_val),
                );
                let esm_agg_commit = compute_esm_aggregate_commitment(
                    &ctx.session_id,
                    &dkg_root,
                    recipient_id,
                    &accepted_participant_ids,
                    committed_use.slot_id,
                    ark_bn254::Fr::from(esm_val),
                );
                DecryptNizkMode::CommittedSmudge {
                    slot_id: committed_use.slot_id,
                    decrypt_round: committed_use.decrypt_round,
                    ciphertext_hash,
                    accepted_participant_ids,
                    sk_agg_commit,
                    esm_agg_commit,
                }
            }
            (None, None) => DecryptNizkMode::LegacyLocalSmudge,
            _ => return Err(PvssError::InvalidShare),
        };

        let expected_sk_agg_share = effective_sk_share.ok_or(PvssError::InvalidShare)?;
        let statement = DecryptNizkStatement {
            session_id: ctx.session_id.clone(),
            party_index,
            ciphertext_u: ciphertext_u.to_vec(),
            ciphertext_v,
            decrypted_share_bytes: decrypted_share_bytes.clone(),
            party_pk: party_pk.to_vec(),
            epoch: ctx.epoch,
            dkg_root,
            expected_sk_agg_share,
            dealer_index: ctx.dealer_index,
            mode,
        };
        let proof = DecryptNizkProver::prove(&statement, witness)?;

        Ok(DecryptedShare {
            index: party_index,
            share_bytes: ShareSecret::new(decrypted_share_bytes),
            proof: ProtocolBytes(proof.proof_bytes),
        })
    }

    fn verify_decrypted_share(&self, share: &DecryptedShare) -> Result<(), PvssError> {
        let proof = DecryptNizkProof::from_bytes(share.proof.0.clone())?;
        let opened = proof.decode()?;
        if opened.statement.party_index != share.index {
            return Err(PvssError::InvalidShare);
        }
        if opened.statement.decrypted_share_bytes != share.share_bytes.expose() {
            return Err(PvssError::InvalidShare);
        }
        if opened.statement.party_index != share.index
            || opened.statement.decrypted_share_bytes != share.share_bytes.expose()
        {
            return Err(PvssError::InvalidShare);
        }

        DecryptNizkVerifier::verify(&opened.statement, &proof)
            .map_err(|e| PvssError::ShareVerification(format!("decrypt NIZK: {e}")))
    }
}

impl PvssAdapter for LatticePvssBfvAdapter {
    fn deal(
        &self,
        secret: &[u8],
        recipient_pks: &[Vec<u8>],
        ctx: &PvssContext,
    ) -> Result<EncryptedShares, PvssError> {
        self.deal_with_rng(secret, recipient_pks, ctx, &mut OsRng)
    }

    fn verify_shares(&self, shares: &EncryptedShares, ctx: &PvssContext) -> Result<(), PvssError> {
        validate_context(ctx)?;
        if shares.backend_id != BACKEND_ID {
            return Err(PvssError::InvalidShare);
        }
        if shares.ciphertexts.len() != ctx.n || shares.proofs.len() != ctx.n {
            return Err(PvssError::InvalidShare);
        }
        let dkg_root = share_proof_dkg_root(ctx)?;
        let bfv_params_digest = canonical_bfv_params_digest().to_vec();

        for (index, (ciphertext_u, proof_bytes)) in shares
            .ciphertexts
            .iter()
            .zip(shares.proofs.iter())
            .enumerate()
        {
            let proof = ShareNizkProof::from_bytes(proof_bytes.clone())?;
            let opened = proof.decode()?;
            let statement = ShareNizkStatement {
                session_id: ProtocolBytes(ctx.session_id.clone()),
                dealer_index: opened.statement.dealer_index,
                recipient_index: index,
                recipient_pk: opened.statement.recipient_pk.clone(),
                bfv_params_digest: ProtocolBytes(bfv_params_digest.clone()),
                dkg_root: ProtocolBytes(dkg_root.clone()),
                ciphertext_u: ProtocolBytes(ciphertext_u.clone()),
                ciphertext_v: ProtocolBytes(compute_ciphertext_v(ciphertext_u).to_vec()),
                share_commitment: opened.statement.share_commitment.clone(),
            };

            ShareNizkVerifier::verify(self.backend.as_ref(), &statement, &proof)?;
        }

        if let Some(ref pp_bytes) = shares.parity_proof {
            let proof = crate::parity::deserialize_parity_proof(pp_bytes).ok_or_else(|| {
                PvssError::ShareVerification("parity proof deserialization failed".into())
            })?;

            let enc_validity_data: Vec<u8> = shares.ciphertexts.iter().flatten().copied().collect();
            let expected_enc_hash = crate::parity::hash_encryption_validity(&enc_validity_data);

            let expected_norm_hash = if !shares.share_bytes.is_empty() {
                let first_len = shares.share_bytes[0].len();
                if first_len < LENGTH_PREFIX_LEN + FR_SERIALIZED_LEN {
                    return Err(PvssError::ShareVerification(
                        "share payload too short for norm witness recovery".into(),
                    ));
                }
                let original_len = u32::from_be_bytes(
                    shares.share_bytes[0][..LENGTH_PREFIX_LEN]
                        .try_into()
                        .map_err(|_| PvssError::ShareVerification("original_len parse".into()))?,
                ) as usize;
                let num_chunks = (first_len - LENGTH_PREFIX_LEN) / FR_SERIALIZED_LEN;
                let needed = ctx.t;
                if shares.share_bytes.len() < needed {
                    return Err(PvssError::ShareVerification(format!(
                        "need {needed} shares for norm witness recovery, got {}",
                        shares.share_bytes.len()
                    )));
                }
                let mut recovered_frs = Vec::with_capacity(num_chunks);
                for chunk_idx in 0..num_chunks {
                    let points: Vec<(usize, Fr)> = shares.share_bytes[..needed]
                        .iter()
                        .enumerate()
                        .map(|(i, payload)| {
                            let offset = LENGTH_PREFIX_LEN + chunk_idx * FR_SERIALIZED_LEN;
                            let arr: &[u8; FR_SERIALIZED_LEN] = payload
                                [offset..offset + FR_SERIALIZED_LEN]
                                .try_into()
                                .expect("share payload chunk alignment");
                            (i + 1, bytes32_to_fr(arr).expect("share Fr out of range"))
                        })
                        .collect();
                    let recovered = crate::shamir::recover(&points, needed).map_err(|_| {
                        PvssError::ShareVerification(format!(
                            "norm witness recovery failed for chunk {chunk_idx}"
                        ))
                    })?;
                    recovered_frs.push(recovered);
                }
                let secret_bytes = frs_to_secret(&recovered_frs, original_len);
                crate::parity::hash_norm_witness(&secret_bytes)
            } else {
                return Err(PvssError::ShareVerification(
                    "no shares for norm witness recovery".into(),
                ));
            };

            for (party_idx, payload) in shares.share_bytes.iter().enumerate() {
                let fr_data = &payload[4..];
                let mut share_frs = Vec::new();
                for chunk in fr_data.chunks(32) {
                    let arr: &[u8; 32] = chunk.try_into().map_err(|_| {
                        PvssError::ShareVerification("share chunk misaligned".into())
                    })?;
                    let fr = bytes32_to_fr(arr).ok_or_else(|| {
                        PvssError::ShareVerification("share Fr out of range".into())
                    })?;
                    share_frs.push(fr);
                }
                let idx = party_idx + 1;
                if !crate::parity::verify_parity(
                    &share_frs,
                    idx,
                    &proof,
                    expected_norm_hash,
                    expected_enc_hash,
                ) {
                    return Err(PvssError::ShareVerification(format!(
                        "parity proof: share {idx} not on RS codeword or witness hash mismatch"
                    )));
                }
            }
        }

        if !shares.share_bytes.is_empty() {
            verify_share_rs_consistency(&shares.share_bytes, ctx.t).map_err(|e| {
                PvssError::ShareVerification(format!("cross-share RS parity check failed: {e}"))
            })?;
        }

        Ok(())
    }

    fn recover(
        &self,
        decrypted_shares: &[DecryptedShare],
        ctx: &PvssContext,
    ) -> Result<Vec<u8>, PvssError> {
        validate_context(ctx)?;
        if decrypted_shares.len() < ctx.t {
            return Err(PvssError::RecoveryFailed);
        }

        let selected = &decrypted_shares[..ctx.t];

        // Validate share payload consistency.
        if selected.is_empty() {
            return Err(PvssError::RecoveryFailed);
        }
        let share_len = selected[0].share_bytes.expose().len();
        if share_len < LENGTH_PREFIX_LEN + FR_SERIALIZED_LEN {
            return Err(PvssError::InvalidShare);
        }
        // Shares must all have identical length.
        if selected
            .iter()
            .any(|share| share.share_bytes.expose().len() != share_len)
        {
            return Err(PvssError::InvalidShare);
        }
        // Share indices must be in-bounds.
        if selected.iter().any(|share| share.index >= ctx.n) {
            return Err(PvssError::InvalidShare);
        }

        // Verify NIZK proofs.
        for share in selected {
            self.verify_decrypted_share(share)?;
        }

        // Check for duplicate indices.
        let mut seen = vec![false; ctx.n];
        for share in selected {
            if seen[share.index] {
                return Err(PvssError::InvalidShare);
            }
            seen[share.index] = true;
        }

        // Parse each share's payload into its component Fr values.
        // Payload format: [ original_len: u32 BE ][ fr_0: 32 bytes ][ fr_1: 32 bytes ]...
        let (original_len, share_frs_by_party) = deserialize_share_payloads(selected)?;
        let num_chunks = share_frs_by_party[0].len();
        if num_chunks == 0 {
            return Err(PvssError::InvalidShare);
        }

        // Recover each chunk independently via Lagrange interpolation.
        let mut recovered_frs = Vec::with_capacity(num_chunks);
        for chunk_idx in 0..num_chunks {
            let chunk_shares: Vec<(usize, Fr)> = share_frs_by_party
                .iter()
                .enumerate()
                .map(|(i, party_frs)| {
                    // x-coordinate = 1-based share index.
                    (selected[i].index + 1, party_frs[chunk_idx])
                })
                .collect();

            let recovered =
                shamir::recover(&chunk_shares, ctx.t).map_err(|_| PvssError::RecoveryFailed)?;
            recovered_frs.push(recovered);
        }

        // Convert recovered Fr elements back to the original byte form.
        Ok(frs_to_secret(&recovered_frs, original_len))
    }

    fn backend_id(&self) -> &'static str {
        BACKEND_ID
    }
}

// ── context validation ─────────────────────────────────────────────────

fn validate_context(ctx: &PvssContext) -> Result<(), PvssError> {
    if ctx.n > MAX_PARTIES {
        return Err(PvssError::BackendError(format!(
            "invalid PVSS context: n={} exceeds maximum supported parties {}",
            ctx.n, MAX_PARTIES
        )));
    }
    if ctx.n == 0 || ctx.t == 0 || ctx.t > ctx.n {
        return Err(PvssError::BackendError(format!(
            "invalid PVSS context: n={}, t={}",
            ctx.n, ctx.t
        )));
    }
    Ok(())
}

pub fn share_proof_dkg_root(ctx: &PvssContext) -> Result<Vec<u8>, PvssError> {
    if ctx.dkg_root.is_empty() {
        return Err(PvssError::BackendError(
            "dkg_root is empty — must be set to bind proofs to a specific DKG ceremony".to_string(),
        ));
    }
    Ok(ctx.dkg_root.clone())
}

// ── secret ↔ Fr conversion ─────────────────────────────────────────────

/// Split arbitrary bytes into 31-byte padded chunks and convert each chunk
/// into a BN254 scalar field element.
///
/// Each chunk is zero-padded to 32 bytes, interpreted as a little-endian u256,
/// and converted to `Fr` via the canonical `BigInt` path (NOT via
/// `from_le_bytes_mod_order`, so values ≥ modulus are rejected).  Since each
/// chunk contains at most 31 bytes of actual data (248 bits), the resulting
/// integer is always strictly less than the BN254 scalar modulus.
fn secret_to_frs(secret: &[u8]) -> Vec<Fr> {
    let num_chunks = secret.len().div_ceil(FR_CHUNK_BYTES);
    let mut frs = Vec::with_capacity(num_chunks);

    for chunk_bytes in secret.chunks(FR_CHUNK_BYTES) {
        let mut padded = [0u8; FR_SERIALIZED_LEN];
        padded[..chunk_bytes.len()].copy_from_slice(chunk_bytes);
        let fr = bytes32_to_fr(&padded).expect("31 data bytes always < Fr modulus");
        frs.push(fr);
    }

    frs
}

/// Reconstruct the original secret bytes from recovered `Fr` elements.
///
/// Each `Fr` is serialized to a fixed 32-byte representation and truncated to
/// 31 data-bearing bytes. The result is then sliced to `original_len`.
fn frs_to_secret(frs: &[Fr], original_len: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(original_len);

    for fr in frs {
        let bytes = fr_to_bytes32(fr);
        let take = FR_CHUNK_BYTES.min(original_len - result.len());
        result.extend_from_slice(&bytes[..take]);
        if result.len() >= original_len {
            break;
        }
    }

    result.truncate(original_len);
    result
}

/// Serialize an `Fr` element to a fixed 32-byte little-endian representation
/// by extracting the 4 × u64 limbs of the underlying `BigInt<4>`.
fn fr_to_bytes32(fr: &Fr) -> [u8; FR_SERIALIZED_LEN] {
    let bigint: ark_ff::BigInt<4> = fr.into_bigint();
    let mut bytes = [0u8; FR_SERIALIZED_LEN];
    for (i, limb) in bigint.0.iter().enumerate() {
        let start = i * 8;
        bytes[start..start + 8].copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

/// Deserialize a 32-byte slice into an `Fr` element.
///
/// Returns `None` if the encoded integer is ≥ the BN254 scalar modulus.
fn bytes32_to_fr(bytes: &[u8; FR_SERIALIZED_LEN]) -> Option<Fr> {
    let mut limbs = [0u64; 4];
    for (i, chunk) in bytes.chunks_exact(8).enumerate() {
        limbs[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    let bigint = ark_ff::BigInt::<4>::new(limbs);
    Fr::from_bigint(bigint)
}

// ── share payload serialization ─────────────────────────────────────────

/// Serialize a per-party vector of `Fr` values into a byte blob for FHE
/// encryption.
///
/// Payload format (all fields little-endian):
///
/// ```text
/// ┌──────────────────┬──────────────────┬─────────────┬──────────────────┐
/// │ original_len     │ fr_0             │ fr_1        │  …               │
/// │ (4 bytes, BE)    │ (32 bytes, LE)   │ (32 bytes)  │                  │
/// └──────────────────┴──────────────────┴─────────────┴──────────────────┘
/// ```
fn serialize_share_payload(share_frs: &[Fr], original_len: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(LENGTH_PREFIX_LEN + share_frs.len() * FR_SERIALIZED_LEN);
    let len_bytes = (original_len as u32).to_be_bytes();
    payload.extend_from_slice(&len_bytes);
    for fr in share_frs {
        payload.extend_from_slice(&fr_to_bytes32(fr));
    }
    payload
}

/// Parse the share payloads from a set of decrypted shares, returning the
/// original secret length and a vector-per-party of recovered `Fr` values.
///
/// All parties' payloads must have the identical structure.
fn deserialize_share_payloads(
    selected: &[DecryptedShare],
) -> Result<(usize, Vec<Vec<Fr>>), PvssError> {
    let first_payload = selected[0].share_bytes.expose();
    let original_len = u32::from_be_bytes(
        first_payload[..LENGTH_PREFIX_LEN]
            .try_into()
            .map_err(|_| PvssError::InvalidShare)?,
    ) as usize;

    let num_chunks = (first_payload.len() - LENGTH_PREFIX_LEN) / FR_SERIALIZED_LEN;
    if !(first_payload.len() - LENGTH_PREFIX_LEN).is_multiple_of(FR_SERIALIZED_LEN) {
        return Err(PvssError::InvalidShare);
    }

    for share in selected.iter().skip(1) {
        let payload = share.share_bytes.expose();
        if payload.len() != first_payload.len() {
            return Err(PvssError::InvalidShare);
        }
        let len = u32::from_be_bytes(
            payload[..LENGTH_PREFIX_LEN]
                .try_into()
                .map_err(|_| PvssError::InvalidShare)?,
        ) as usize;
        if len != original_len {
            return Err(PvssError::InvalidShare);
        }
    }

    let mut share_frs_by_party = Vec::with_capacity(selected.len());
    for share in selected {
        let payload = share.share_bytes.expose();
        let mut frs = Vec::with_capacity(num_chunks);
        for chunk_start in (LENGTH_PREFIX_LEN..payload.len()).step_by(FR_SERIALIZED_LEN) {
            let chunk: &[u8; FR_SERIALIZED_LEN] = payload
                [chunk_start..chunk_start + FR_SERIALIZED_LEN]
                .try_into()
                .map_err(|_| PvssError::InvalidShare)?;
            let fr = bytes32_to_fr(chunk).ok_or(PvssError::InvalidShare)?;
            frs.push(fr);
        }
        share_frs_by_party.push(frs);
    }

    Ok((original_len, share_frs_by_party))
}

// ── cross-share RS consistency ─────────────────────────────────────────

/// Verify that all plaintext shares in `share_bytes` form valid RS codewords
/// (evaluations of the same degree-`(threshold-1)` polynomial) for each Fr chunk.
///
/// This prevents the share-poisoning attack where a dishonest dealer creates
/// individually-valid NIZK proofs for shares that reconstruct garbage.
/// Equivalent to the RS parity portion of `share_computation::verify_batched_share_computation`.
fn verify_share_rs_consistency(share_bytes: &[Vec<u8>], threshold: usize) -> Result<(), String> {
    let n = share_bytes.len();
    if n == 0 {
        return Ok(());
    }
    let first_len = share_bytes[0].len();
    if first_len < LENGTH_PREFIX_LEN + FR_SERIALIZED_LEN {
        return Err("share payload too short".to_string());
    }
    let data_len = first_len - LENGTH_PREFIX_LEN;
    if !data_len.is_multiple_of(FR_SERIALIZED_LEN) {
        return Err("share payload misaligned".to_string());
    }
    let num_chunks = data_len / FR_SERIALIZED_LEN;

    // All shares must have identical length.
    if share_bytes.iter().any(|b| b.len() != first_len) {
        return Err("inconsistent share payload lengths".to_string());
    }

    // Parse all Fr values: party_frs[party][chunk] = Fr
    let mut party_frs: Vec<Vec<Fr>> = Vec::with_capacity(n);
    for payload in share_bytes {
        let mut frs = Vec::with_capacity(num_chunks);
        for chunk_start in (LENGTH_PREFIX_LEN..first_len).step_by(FR_SERIALIZED_LEN) {
            let chunk: &[u8; FR_SERIALIZED_LEN] = payload
                [chunk_start..chunk_start + FR_SERIALIZED_LEN]
                .try_into()
                .map_err(|_| "share payload chunk alignment".to_string())?;
            let fr = bytes32_to_fr(chunk).ok_or("share field element out of range".to_string())?;
            frs.push(fr);
        }
        party_frs.push(frs);
    }

    let degree = threshold.saturating_sub(1);
    let min_points = degree + 1;
    if n < min_points {
        return Err(format!(
            "insufficient shares for RS check: need {min_points}, got {n}"
        ));
    }

    // For each chunk, verify RS low-degree property.
    for chunk_idx in 0..num_chunks {
        let points: Vec<(Fr, Fr)> = party_frs
            .iter()
            .enumerate()
            .map(|(i, frs)| (Fr::from((i + 1) as u64), frs[chunk_idx]))
            .collect();

        // Interpolate from first `min_points` shares.
        let coefficients = interpolate_bn254(&points[..min_points])
            .map_err(|_| format!("chunk {chunk_idx}: interpolation failed"))?;

        // Verify all shares match the polynomial.
        for (i, frs) in party_frs.iter().enumerate() {
            let x = Fr::from((i + 1) as u64);
            let expected = eval_bn254_poly_coeffs(&coefficients, x);
            if expected != frs[chunk_idx] {
                return Err(format!(
                    "chunk {chunk_idx}: share {i} is not on the RS codeword"
                ));
            }
        }
    }

    Ok(())
}

/// Lagrange interpolation over BN254 Fr, returning coefficients low-to-high degree.
fn interpolate_bn254(points: &[(Fr, Fr)]) -> Result<Vec<Fr>, ()> {
    let degree = points.len() - 1;
    let mut coefficients = vec![Fr::ZERO; degree + 1];
    for (i, (x_i, y_i)) in points.iter().enumerate() {
        let mut basis = vec![Fr::ONE];
        let mut denominator = Fr::ONE;
        for (j, (x_j, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            denominator *= *x_i - *x_j;
            let mut new_basis = vec![Fr::ZERO; basis.len() + 1];
            for (k, coeff) in basis.iter().enumerate() {
                new_basis[k] += *coeff * (-*x_j);
                new_basis[k + 1] += *coeff;
            }
            basis = new_basis;
        }
        let inv = denominator.inverse().ok_or(())?;
        let scale = *y_i * inv;
        for (k, coeff) in basis.iter().enumerate() {
            coefficients[k] += *coeff * scale;
        }
    }
    Ok(coefficients)
}

/// Evaluate a polynomial at x (coefficients in low-to-high order).
fn eval_bn254_poly_coeffs(coefficients: &[Fr], x: Fr) -> Fr {
    coefficients
        .iter()
        .rev()
        .fold(Fr::ZERO, |acc, coeff| acc * x + coeff)
}

// ── helpers ─────────────────────────────────────────────────────────────

pub fn compute_poly_factors(n: usize, t: usize, r: ark_bn254::Fr) -> Vec<ark_bn254::Fr> {
    use ark_ff::AdditiveGroup;

    let n_rows = if n > t + 1 { n - t - 1 } else { 0 };
    let mut factors = vec![ark_bn254::Fr::ZERO; n];

    if n_rows == 0 {
        return factors;
    }

    let order = t + 1;

    // Precompute binomial coefficients C(order, j) for j=0..order
    let mut binom = Vec::with_capacity(order + 1);
    binom.push(ark_bn254::Fr::from(1u64));
    for j in 0..order {
        let next = binom[j]
            * ark_bn254::Fr::from((order - j) as u64)
            * ark_bn254::Fr::from((j + 1) as u64)
                .inverse()
                .expect("j+1 < Fr modulus");
        binom.push(next);
    }

    // Schwartz-Zippel: combine all parity-check rows with powers of r.
    // factor_p = Σ_{i: 0 ≤ p−i ≤ order, 0 ≤ i < n_rows} r^i · (−1)^{order−(p−i)} · C(order, p−i)
    for (p, factor) in factors.iter_mut().enumerate() {
        let lo = p.saturating_sub(order);
        let hi = (p).min(n_rows - 1);
        let mut acc = ark_bn254::Fr::ZERO;
        let mut r_pow = r.pow([lo as u64]); // r^lo
        for i in lo..=hi {
            let jj = p - i; // j in 0..=order
            let sign = if (order - jj).is_multiple_of(2) {
                ark_bn254::Fr::ONE
            } else {
                -ark_bn254::Fr::ONE
            };
            acc += r_pow * sign * binom[jj];
            r_pow *= r;
        }
        *factor = acc;
    }
    factors
}

fn map_fhe_error(error: FheError) -> PvssError {
    PvssError::BackendError(error.to_string())
}

// ── Deterministic deal path (P1: pre-computation during keygen) ────────

impl LatticePvssBfvAdapter {
    /// Deterministic deal: same logic as [`PvssAdapter::deal`] but with a
    /// seeded RNG so the output is reproducible across calls.
    ///
    /// **⚠️ RESEARCH ONLY** — see [`deal_seeded`].
    pub fn deal_seeded(
        &self,
        secret: &[u8],
        recipient_pks: &[Vec<u8>],
        ctx: &PvssContext,
        seed: &[u8; 32],
    ) -> Result<EncryptedShares, PvssError> {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        let mut shamir_rng = ChaCha20Rng::from_seed(*seed);
        self.deal_with_rng(secret, recipient_pks, ctx, &mut shamir_rng)
    }

    /// Shared deal implementation parameterised by a supplied RNG.
    fn deal_with_rng<R: RngCore>(
        &self,
        secret: &[u8],
        recipient_pks: &[Vec<u8>],
        ctx: &PvssContext,
        rng: &mut R,
    ) -> Result<EncryptedShares, PvssError> {
        validate_context(ctx)?;
        if recipient_pks.len() != ctx.n {
            return Err(PvssError::InvalidShare);
        }

        let secret_frs = secret_to_frs(secret);
        let num_chunks = secret_frs.len();

        let mut party_shares: Vec<Vec<Fr>> = vec![Vec::with_capacity(num_chunks); ctx.n];

        for secret_fr in &secret_frs {
            let chunk_shares = shamir::split(secret_fr, ctx.n, ctx.t, rng)
                .map_err(|e| PvssError::BackendError(format!("shamir split: {e}")))?;
            for (x, share_value) in chunk_shares {
                party_shares[x - 1].push(share_value);
            }
        }

        let chunk_shares: Vec<Vec<Fr>> = (0..num_chunks)
            .map(|chunk| party_shares.iter().map(|ps| ps[chunk]).collect())
            .collect();

        let all_share_bytes: Vec<Vec<u8>> = party_shares
            .iter()
            .map(|shares| serialize_share_payload(shares, secret.len()))
            .collect();

        let mut ciphertexts = Vec::with_capacity(ctx.n);
        let mut proofs = Vec::with_capacity(ctx.n);
        let dkg_root = share_proof_dkg_root(ctx)?;
        let bfv_params_digest = canonical_bfv_params_digest().to_vec();

        for (index, (share_bytes, recipient_pk_bytes)) in
            all_share_bytes.iter().zip(recipient_pks.iter()).enumerate()
        {
            let recipient_pk = PublicKey {
                bytes: recipient_pk_bytes.clone(),
            };
            let mut randomness = [0u8; 32];
            rng.fill_bytes(&mut randomness);
            let mut enc_rng = rand_chacha::ChaCha20Rng::from_seed(randomness);
            let ciphertext_u = self
                .backend
                .encrypt(&recipient_pk, share_bytes, &mut enc_rng)
                .map(|ciphertext| ciphertext.bytes)
                .map_err(map_fhe_error)?;

            let share_commitment = compute_share_commitment(&ctx.session_id, index, share_bytes);
            let ciphertext_v = compute_ciphertext_v(&ciphertext_u);
            let statement = ShareNizkStatement {
                session_id: ProtocolBytes(ctx.session_id.clone()),
                dealer_index: ctx.dealer_index,
                recipient_index: index,
                recipient_pk: ProtocolBytes(recipient_pk_bytes.clone()),
                bfv_params_digest: ProtocolBytes(bfv_params_digest.clone()),
                dkg_root: ProtocolBytes(dkg_root.clone()),
                ciphertext_u: ProtocolBytes(ciphertext_u.clone()),
                ciphertext_v: ProtocolBytes(ciphertext_v.to_vec()),
                share_commitment: ProtocolBytes(share_commitment.to_vec()),
            };
            let witness = ShareNizkWitness {
                share_bytes: ShareSecret::new(share_bytes.clone()),
                encryption_randomness: EncRandomness::new(randomness.to_vec()),
            };
            let proof = ShareNizkProver::prove(self.backend.as_ref(), &statement, &witness, None)?;

            ciphertexts.push(ciphertext_u);
            proofs.push(proof.proof_bytes.0);
        }

        let enc_validity_data: Vec<u8> = ciphertexts.iter().flatten().copied().collect();
        let parity_proof_bytes =
            crate::parity::prove_parity(&chunk_shares, ctx.n, ctx.t, secret, &enc_validity_data)
                .map(|pp| crate::parity::serialize_parity_proof(&pp));

        Ok(EncryptedShares {
            ciphertexts,
            share_bytes: all_share_bytes.clone(),
            proofs,
            parity_proof: parity_proof_bytes,
            backend_id: BACKEND_ID.to_owned(),
        })
    }
}
