use pvthfhe_fhe::{
    types::{Ciphertext, DecryptShare},
    FheBackend, FheError,
};
use pvthfhe_pvss::{
    nizk_decrypt::{
        DecryptNizkMode, DecryptNizkProof, DecryptNizkProver,
        DecryptNizkStatement, DecryptNizkVerifier, DecryptNizkWitness,
    },
    nizk_share::compute_ciphertext_v,
};
use pvthfhe_types::{ProtocolBytes, Secret};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const FINAL_AGGREGATION_PROOF_VERSION: u16 = 1;
const FINAL_AGGREGATION_DOMAIN: &[u8] = b"pvthfhe-final-decrypt-aggregation-v1";
const FINAL_PLAINTEXT_HASH_DOMAIN: &[u8] = b"pvthfhe-final-plaintext-hash-v1";

#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    #[error("invalid share from party {party_id}")]
    InvalidShare { party_id: u32 },
    #[error("insufficient shares: need {needed}, got {got}")]
    InsufficientShares { needed: usize, got: usize },
    #[error("duplicate party id {0}")]
    DuplicateParty(u32),
    #[error("unknown party id {0}")]
    UnknownParty(u32),
    #[error("NIZK verification failed for party {party_id}")]
    NizkVerify { party_id: u32 },
    #[error("backend error: {0}")]
    Backend(#[from] FheError),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DkgFoldPublicAnchors {
    pub dkg_root: [u8; 32],
    pub aggregated_pk_commit: [u8; 32],
    pub participant_set_hash: [u8; 32],
    pub sk_agg_commits_root: [u8; 32],
    pub esm_agg_commits_root: [u8; 32],
    pub smudge_slot_policy_hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecryptionFoldPublicAnchors {
    pub dkg_root: [u8; 32],
    pub ciphertext_hash: [u8; 32],
    pub expected_sk_commits_root: [u8; 32],
    pub expected_esm_commits_root: [u8; 32],
    pub slot_id: u64,
    pub decrypt_round: u64,
    pub plaintext_hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptSharePayload {
    pub party_id: u32,
    pub pk_i_hash: [u8; 32],
    pub dkg_root: [u8; 32],
    pub ciphertext_hash: [u8; 32],
    pub epoch: u64,
    pub share: DecryptShare,
    pub nizk: ProtocolBytes,
    pub version: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct C6DecryptProofRef {
    pub dkg_root: [u8; 32],
    pub ciphertext_hash: [u8; 32],
    pub participant_id: u16,
    pub decrypt_share_commitment: [u8; 32],
    pub proof_digest: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenDecryptShare {
    pub participant_id: u16,
    pub share_value_mod_plaintext: u64,
    pub proof_digest: [u8; 32],
    pub proof_ref: C6DecryptProofRef,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LagrangeCoefficientClaim {
    pub participant_id: u16,
    pub coefficient_mod_plaintext: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrtReconstructionClaim {
    pub moduli: Vec<u64>,
    pub residues: Vec<u64>,
    pub reconstructed_mod_plaintext: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlaintextEncodingClaim {
    pub plaintext_modulus: u64,
    pub decoded_plaintext: Vec<u8>,
    pub slots: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalAggregationStatement {
    pub session_id: Vec<u8>,
    pub dkg_root: [u8; 32],
    pub ciphertext_hash: [u8; 32],
    pub plaintext_hash: [u8; 32],
    pub threshold: usize,
    pub accepted_participant_ids: Vec<u16>,
    pub selected_shares: Vec<ProvenDecryptShare>,
    pub lagrange_coefficients: Vec<LagrangeCoefficientClaim>,
    pub combined_share_mod_plaintext: u64,
    pub crt: CrtReconstructionClaim,
    pub plaintext_encoding: PlaintextEncodingClaim,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalAggregationProof {
    pub version: u16,
    pub statement_digest: [u8; 32],
    pub relation_digest: [u8; 32],
}

pub fn partial_decrypt(
    backend: &impl FheBackend,
    ct: &Ciphertext,
    party_id: u32,
    dkg_root: &[u8; 32],
    ciphertext_hash: &[u8; 32],
    epoch: u64,
    party_pk_bytes: &[u8],
    secret_key_bytes: Option<&[u8]>,
    rng: &mut dyn RngCore,
) -> Result<DecryptSharePayload, DecryptError> {
    let (share, witness) = match backend.partial_decrypt_with_witness(ct, party_id, rng) {
        Ok(result) => result,
        Err(FheError::Backend { .. }) => {
            let share = backend.partial_decrypt(ct, party_id, rng)?;
            return Ok(DecryptSharePayload {
                party_id,
                pk_i_hash: sha256_bytes(party_pk_bytes),
                dkg_root: *dkg_root,
                ciphertext_hash: *ciphertext_hash,
                epoch,
                share,
                nizk: ProtocolBytes(vec![]),
                version: 1,
            });
        }
        Err(e) => return Err(DecryptError::Backend(e)),
    };

    let pk_i_hash = sha256_bytes(party_pk_bytes);

    // Generate real NIZK proof when secret key is available
    let nizk_proof_bytes = if let Some(sk_bytes) = secret_key_bytes {
        if sk_bytes.is_empty() || party_pk_bytes.is_empty() {
            ProtocolBytes(vec![])
        } else {
            let party_index = (party_id.saturating_sub(1)) as usize;
            let session_id = dkg_root.to_vec();
            let ciphertext_u = ct.bytes.clone();
            let ciphertext_v = compute_ciphertext_v(&ciphertext_u).to_vec();
            let decrypted_share_bytes = witness.decrypted_share_bytes.clone();

            let decryption_noise_bytes = witness.esm_noise_poly_bytes.clone();

            let stmt = DecryptNizkStatement {
                session_id,
                party_index,
                ciphertext_u,
                ciphertext_v,
                decrypted_share_bytes,
                party_pk: party_pk_bytes.to_vec(),
                epoch,
                dkg_root: dkg_root.to_vec(),
                mode: DecryptNizkMode::LegacyLocalSmudge,
            };

            let witness = DecryptNizkWitness {
                secret_key_bytes: Secret::new(sk_bytes.to_vec()),
                decryption_noise: Secret::new(decryption_noise_bytes),
                sk_agg_share: None,
                esm_agg_share: None,
                esm_noise_poly_bytes: None,
            };

            match DecryptNizkProver::prove(&stmt, &witness) {
                Ok(proof) => ProtocolBytes(proof.proof_bytes),
                Err(_) => ProtocolBytes(vec![]),
            }
        }
    } else {
        ProtocolBytes(vec![])
    };

    Ok(DecryptSharePayload {
        party_id,
        pk_i_hash,
        dkg_root: *dkg_root,
        ciphertext_hash: *ciphertext_hash,
        epoch,
        share,
        nizk: nizk_proof_bytes,
        version: 1,
    })
}

pub fn prove_final_aggregation(
    stmt: &FinalAggregationStatement,
) -> Result<FinalAggregationProof, DecryptError> {
    validate_final_aggregation_statement(stmt)?;
    Ok(FinalAggregationProof {
        version: FINAL_AGGREGATION_PROOF_VERSION,
        statement_digest: final_aggregation_statement_digest(stmt),
        relation_digest: final_aggregation_relation_digest(stmt),
    })
}

pub fn verify_final_aggregation(
    stmt: &FinalAggregationStatement,
    proof: &FinalAggregationProof,
) -> Result<(), DecryptError> {
    validate_final_aggregation_statement(stmt)?;
    if proof.version != FINAL_AGGREGATION_PROOF_VERSION
        || proof.statement_digest != final_aggregation_statement_digest(stmt)
        || proof.relation_digest != final_aggregation_relation_digest(stmt)
    {
        return Err(DecryptError::InvalidShare { party_id: 0 });
    }
    Ok(())
}

pub fn verify_dkg_decryption_anchor_equality(
    dkg: &DkgFoldPublicAnchors,
    decrypt: &DecryptionFoldPublicAnchors,
) -> Result<(), DecryptError> {
    if dkg.dkg_root != decrypt.dkg_root
        || dkg.sk_agg_commits_root != decrypt.expected_sk_commits_root
        || dkg.esm_agg_commits_root != decrypt.expected_esm_commits_root
    {
        return Err(DecryptError::InvalidShare { party_id: 0 });
    }
    Ok(())
}

pub fn compute_final_plaintext_hash(plaintext: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(FINAL_PLAINTEXT_HASH_DOMAIN);
    h.update((plaintext.len() as u64).to_be_bytes());
    h.update(plaintext);
    h.finalize().into()
}

pub fn aggregate_decrypt(
    backend: &impl FheBackend,
    ct: &Ciphertext,
    shares: &[DecryptSharePayload],
    threshold: usize,
    allowed_parties: &[u32],
    dkg_root: &[u8; 32],
    ciphertext_hash: &[u8; 32],
    _epoch: u64,
) -> Result<Vec<u8>, DecryptError> {
    let mut seen_parties = HashSet::new();
    let mut valid_shares = Vec::new();

    for payload in shares {
        if !allowed_parties.contains(&payload.party_id) {
            return Err(DecryptError::UnknownParty(payload.party_id));
        }

        if !seen_parties.insert(payload.party_id) {
            return Err(DecryptError::DuplicateParty(payload.party_id));
        }

        if payload.ciphertext_hash != *ciphertext_hash {
            return Err(DecryptError::InvalidShare {
                party_id: payload.party_id,
            });
        }

        if payload.nizk.is_empty() {
            return Err(DecryptError::NizkVerify {
                party_id: payload.party_id,
            });
        }

        let proof = DecryptNizkProof::from_bytes(payload.nizk.0.clone())
            .map_err(|_| DecryptError::NizkVerify {
                party_id: payload.party_id,
            })?;
        let opened = proof.decode().map_err(|_| DecryptError::NizkVerify {
            party_id: payload.party_id,
        })?;

        let party_index = (payload.party_id.saturating_sub(1)) as usize;
        if opened.statement.party_index != party_index
            || opened.statement.dkg_root != dkg_root.to_vec()
            || sha256_bytes(&opened.statement.ciphertext_u) != *ciphertext_hash
            || opened.statement.ciphertext_v
                != compute_ciphertext_v(&opened.statement.ciphertext_u).to_vec()
        {
            return Err(DecryptError::NizkVerify {
                party_id: payload.party_id,
            });
        }

        DecryptNizkVerifier::verify(&opened.statement, &proof).map_err(|_| {
            DecryptError::NizkVerify {
                party_id: payload.party_id,
            }
        })?;

        valid_shares.push(payload.share.clone());
    }

    if valid_shares.len() < threshold {
        return Err(DecryptError::InsufficientShares {
            needed: threshold,
            got: valid_shares.len(),
        });
    }

    Ok(backend.aggregate_decrypt(ct, &valid_shares, threshold)?)
}

fn validate_final_aggregation_statement(
    stmt: &FinalAggregationStatement,
) -> Result<(), DecryptError> {
    let modulus = stmt.plaintext_encoding.plaintext_modulus;
    if stmt.session_id.is_empty()
        || stmt.threshold == 0
        || modulus < 2
        || stmt.accepted_participant_ids.is_empty()
        || stmt.selected_shares.len() < stmt.threshold
        || stmt.selected_shares.len() != stmt.lagrange_coefficients.len()
    {
        return Err(DecryptError::InvalidShare { party_id: 0 });
    }
    validate_strictly_sorted(&stmt.accepted_participant_ids)?;

    let accepted = stmt
        .accepted_participant_ids
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    let mut selected_ids = Vec::with_capacity(stmt.selected_shares.len());
    let mut seen_selected = HashSet::new();
    for share in &stmt.selected_shares {
        if share.participant_id == 0
            || !accepted.contains(&share.participant_id)
            || !seen_selected.insert(share.participant_id)
            || share.share_value_mod_plaintext >= modulus
            || share.proof_digest.iter().all(|byte| *byte == 0)
            || share.proof_ref.participant_id != share.participant_id
            || share.proof_ref.dkg_root != stmt.dkg_root
            || share.proof_ref.ciphertext_hash != stmt.ciphertext_hash
            || share.proof_ref.proof_digest != share.proof_digest
            || share
                .proof_ref
                .decrypt_share_commitment
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(DecryptError::InvalidShare {
                party_id: u32::from(share.participant_id),
            });
        }
        selected_ids.push(share.participant_id);
    }

    let mut combined = 0u64;
    for (share, coeff) in stmt.selected_shares.iter().zip(&stmt.lagrange_coefficients) {
        if coeff.participant_id != share.participant_id
            || coeff.coefficient_mod_plaintext >= modulus
            || coeff.coefficient_mod_plaintext
                != lagrange_coefficient_at_zero_mod(share.participant_id, &selected_ids, modulus)?
        {
            return Err(DecryptError::InvalidShare {
                party_id: u32::from(share.participant_id),
            });
        }
        combined = add_mod(
            combined,
            mul_mod(
                share.share_value_mod_plaintext,
                coeff.coefficient_mod_plaintext,
                modulus,
            ),
            modulus,
        );
    }
    if combined != stmt.combined_share_mod_plaintext % modulus {
        return Err(DecryptError::InvalidShare { party_id: 0 });
    }

    validate_crt(&stmt.crt, modulus, stmt.combined_share_mod_plaintext)?;
    validate_plaintext_decoding(&stmt.plaintext_encoding)?;
    if stmt.plaintext_hash
        != compute_final_plaintext_hash(&stmt.plaintext_encoding.decoded_plaintext)
    {
        return Err(DecryptError::InvalidShare { party_id: 0 });
    }
    Ok(())
}

fn validate_strictly_sorted(values: &[u16]) -> Result<(), DecryptError> {
    if values.iter().any(|value| *value == 0) {
        return Err(DecryptError::InvalidShare { party_id: 0 });
    }
    for window in values.windows(2) {
        if window[0] >= window[1] {
            return Err(DecryptError::InvalidShare { party_id: 0 });
        }
    }
    Ok(())
}

fn lagrange_coefficient_at_zero_mod(
    participant_id: u16,
    selected_ids: &[u16],
    modulus: u64,
) -> Result<u64, DecryptError> {
    let xi = u64::from(participant_id) % modulus;
    let mut numerator = 1u64;
    let mut denominator = 1u64;
    for other in selected_ids {
        if *other == participant_id {
            continue;
        }
        let xj = u64::from(*other) % modulus;
        numerator = mul_mod(numerator, neg_mod(xj, modulus), modulus);
        denominator = mul_mod(denominator, sub_mod(xi, xj, modulus), modulus);
    }
    let inv = mod_inverse(denominator, modulus).ok_or(DecryptError::InvalidShare {
        party_id: u32::from(participant_id),
    })?;
    Ok(mul_mod(numerator, inv, modulus))
}

fn validate_crt(
    crt: &CrtReconstructionClaim,
    plaintext_modulus: u64,
    combined_share: u64,
) -> Result<(), DecryptError> {
    if crt.moduli.is_empty()
        || crt.moduli.len() != crt.residues.len()
        || crt.reconstructed_mod_plaintext >= plaintext_modulus
        || crt.reconstructed_mod_plaintext != combined_share % plaintext_modulus
    {
        return Err(DecryptError::InvalidShare { party_id: 0 });
    }
    let mut seen_moduli = HashSet::new();
    for (&modulus, &residue) in crt.moduli.iter().zip(&crt.residues) {
        if modulus < 2 || residue >= modulus || !seen_moduli.insert(modulus) {
            return Err(DecryptError::InvalidShare { party_id: 0 });
        }
        if crt.reconstructed_mod_plaintext % modulus != residue {
            return Err(DecryptError::InvalidShare { party_id: 0 });
        }
    }
    Ok(())
}

fn validate_plaintext_decoding(encoding: &PlaintextEncodingClaim) -> Result<(), DecryptError> {
    let Some((&original_len, payload_slots)) = encoding.slots.split_first() else {
        return Err(DecryptError::InvalidShare { party_id: 0 });
    };
    if original_len as usize != encoding.decoded_plaintext.len()
        || encoding.decoded_plaintext.len() > payload_slots.len() * 2
    {
        return Err(DecryptError::InvalidShare { party_id: 0 });
    }
    let mut bytes = Vec::with_capacity(payload_slots.len() * 2);
    for slot in payload_slots {
        if *slot >= encoding.plaintext_modulus {
            return Err(DecryptError::InvalidShare { party_id: 0 });
        }
        bytes.push((slot & 0xff) as u8);
        bytes.push(((slot >> 8) & 0xff) as u8);
    }
    bytes.truncate(original_len as usize);
    if bytes != encoding.decoded_plaintext {
        return Err(DecryptError::InvalidShare { party_id: 0 });
    }
    Ok(())
}

fn final_aggregation_statement_digest(stmt: &FinalAggregationStatement) -> [u8; 32] {
    let mut h = Sha256::new();
    absorb_final_statement(&mut h, stmt);
    h.finalize().into()
}

fn final_aggregation_relation_digest(stmt: &FinalAggregationStatement) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(FINAL_AGGREGATION_DOMAIN);
    h.update(b"relation");
    h.update(stmt.threshold.to_be_bytes());
    h.update((stmt.selected_shares.len() as u64).to_be_bytes());
    h.update(stmt.combined_share_mod_plaintext.to_be_bytes());
    h.update(stmt.crt.reconstructed_mod_plaintext.to_be_bytes());
    h.update(stmt.plaintext_encoding.plaintext_modulus.to_be_bytes());
    h.update((stmt.plaintext_encoding.decoded_plaintext.len() as u64).to_be_bytes());
    h.update(&stmt.plaintext_encoding.decoded_plaintext);
    h.finalize().into()
}

fn absorb_final_statement(h: &mut Sha256, stmt: &FinalAggregationStatement) {
    h.update(FINAL_AGGREGATION_DOMAIN);
    absorb_bytes(h, &stmt.session_id);
    h.update(stmt.dkg_root);
    h.update(stmt.ciphertext_hash);
    h.update(stmt.plaintext_hash);
    h.update(stmt.threshold.to_be_bytes());
    absorb_u16s(h, &stmt.accepted_participant_ids);
    h.update((stmt.selected_shares.len() as u64).to_be_bytes());
    for share in &stmt.selected_shares {
        h.update(share.participant_id.to_be_bytes());
        h.update(share.share_value_mod_plaintext.to_be_bytes());
        h.update(share.proof_digest);
        h.update(share.proof_ref.dkg_root);
        h.update(share.proof_ref.ciphertext_hash);
        h.update(share.proof_ref.participant_id.to_be_bytes());
        h.update(share.proof_ref.decrypt_share_commitment);
        h.update(share.proof_ref.proof_digest);
    }
    h.update((stmt.lagrange_coefficients.len() as u64).to_be_bytes());
    for coeff in &stmt.lagrange_coefficients {
        h.update(coeff.participant_id.to_be_bytes());
        h.update(coeff.coefficient_mod_plaintext.to_be_bytes());
    }
    h.update(stmt.combined_share_mod_plaintext.to_be_bytes());
    absorb_u64s(h, &stmt.crt.moduli);
    absorb_u64s(h, &stmt.crt.residues);
    h.update(stmt.crt.reconstructed_mod_plaintext.to_be_bytes());
    h.update(stmt.plaintext_encoding.plaintext_modulus.to_be_bytes());
    absorb_bytes(h, &stmt.plaintext_encoding.decoded_plaintext);
    absorb_u64s(h, &stmt.plaintext_encoding.slots);
}

fn absorb_bytes(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
}

fn absorb_u16s(h: &mut Sha256, values: &[u16]) {
    h.update((values.len() as u64).to_be_bytes());
    for value in values {
        h.update(value.to_be_bytes());
    }
}

fn absorb_u64s(h: &mut Sha256, values: &[u64]) {
    h.update((values.len() as u64).to_be_bytes());
    for value in values {
        h.update(value.to_be_bytes());
    }
}

fn add_mod(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    ((lhs as u128 + rhs as u128) % modulus as u128) as u64
}

fn sub_mod(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    ((lhs as u128 + modulus as u128 - rhs as u128) % modulus as u128) as u64
}

fn neg_mod(value: u64, modulus: u64) -> u64 {
    if value % modulus == 0 {
        0
    } else {
        modulus - (value % modulus)
    }
}

fn mul_mod(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    ((lhs as u128 * rhs as u128) % modulus as u128) as u64
}

fn mod_inverse(value: u64, modulus: u64) -> Option<u64> {
    let (mut old_r, mut r) = (i128::from(modulus), i128::from(value % modulus));
    let (mut old_s, mut s) = (0i128, 1i128);
    while r != 0 {
        let quotient = old_r / r;
        (old_r, r) = (r, old_r - quotient * r);
        (old_s, s) = (s, old_s - quotient * s);
    }
    if old_r != 1 {
        return None;
    }
    let modulus = i128::from(modulus);
    Some(((old_s % modulus + modulus) % modulus) as u64)
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
