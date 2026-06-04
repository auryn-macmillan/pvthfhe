//! `CycloNizkAdapter`: wires the Cyclo-companion Ajtai D2 NIZK backend.
//!
//! # Proof byte layout (spec §3.4 + SPEC EXTENSION for sigma_proof_bytes)
//!
//! ```text
//! version                  : u16 BE = 0x0002
//! ccs_instance_id          : 32 bytes
//!                            = SHA256(session_id || participant_id u16 BE
//!                                     || q u64 BE || degree u64 BE
//!                                     || error_bound u64 BE
//!                                     || b"cyclo-ajtai-d2/v1")
//! ajtai_commitment         : 13 × 256 × 8 = 26 624 bytes
//!                            (i64 LE per coefficient, centred mod Q_COMMIT)
//! sha256_binding           : u32 BE session_id_len + session_id bytes
//!                            + participant_id u16 BE + 32-byte commitment
//!                            = stmt.pvss_commitment (Ajtai D2 hash binding)
//! sigma_proof_bytes        : u32 BE total_len            [SPEC EXTENSION — §3.4]
//!   d_rns                  : u32 BE count + count × u64 LE
//!   t_rns                  : u32 BE count + count × u64 LE
//!   z_s                    : u32 BE count + count × i64 LE
//!   z_e                    : u32 BE count + count × i64 LE
//!   ch                     : 32 bytes (sign-extended ternary scalar: -1, 0, or 1)
//! cyclo_accumulator_bytes  : u32 BE length + accumulator transcript
//!                            (versioned Cyclo accumulator, per A1 spec)
//! ```
//!
//! # SPEC EXTENSION note
//!
//! `sigma_proof_bytes` (including the embedded `d_rns`) is NOT present in spec
//! §3.4 as of the current revision.  The field was added because sigma::verify
//! requires a `SigmaStatement` containing `d_rns`, which the verifier cannot
//! derive without the witness.  Flag to Prometheus for spec §3.4 update.
//!
//! # Accumulator Transcript Verification (A1)
//!
//! `cyclo_accumulator_bytes` carries a versioned Cyclo accumulator transcript.
//! The verifier decodes it, cross-checks instance hashes against the NIZK
//! statement, and accepts well-formed transcripts.  Full fold-relation
//! verification (calling `verify_fold` with completeCcsPShareInstance data)
//! is deferred to the aggregator layer where full instance data is available.

use crate::ajtai::{AjtaiCommitment, AjtaiMatrix, AjtaiParams, Rq, AJTAI_RANK, PHI, Q_COMMIT};
use crate::sigma::{self, rlwe_n, SigmaStatement, SigmaWitness};
use crate::{NizkAdapter, NizkError, NizkProof, NizkStatement, NizkWitness, BACKEND_ID};

use pvthfhe_cyclo::accumulator_codec;
use pvthfhe_cyclo::fold::AJTAI_COMMITMENT_BYTES;
use pvthfhe_cyclo::PVTHFHE_CYCLO_PARAMS;

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const PROOF_VERSION: u16 = 0x0002;

/// Maximum allowed proof byte length (prevents heap-exhaustion from crafted proof).
const MAX_PROOF_BYTES: usize = 33_554_432; // 32 MiB — G1: N=8192 × 90-round sigma = 17.7 MB, + margin

/// Maximum ciphertext/share byte length.
const MAX_INPUT_BYTES: usize = 1_048_576; // 1 MiB

/// Maximum session_id length in bytes.
const MAX_SESSION_ID_LEN: usize = 256;

/// Maximum number of participants in a batch_verify call.
const MAX_BATCH_STMTS: usize = 1024;

fn ajtai_m() -> usize {
    rlwe_n() / PHI
}

/// Zero-sized adapter implementing the Cyclo-companion Ajtai D2 NIZK backend.
#[derive(Debug, Default, Clone, Copy)]
pub struct CycloNizkAdapter;

impl NizkAdapter for CycloNizkAdapter {
    fn backend_id(&self) -> &'static str {
        BACKEND_ID
    }

    fn prove(
        &self,
        stmt: &NizkStatement,
        witness: &NizkWitness,
        rng: &mut dyn RngCore,
    ) -> Result<NizkProof, NizkError> {
        validate_statement(stmt)?;
        validate_witness(witness)?;

        let ccs_id = compute_ccs_instance_id(stmt)?;

        let c_rns = expand_c_rns(&ccs_id)?;

        let s_i = pad_or_truncate_to_rlwe_n(&witness.secret_share_poly);
        let e_i = pad_or_truncate_to_rlwe_n(&witness.error);

        let d_rns = sigma::compute_d_rns(&c_rns, &s_i, &e_i)?;

        let ajtai_commitment = compute_ajtai_commitment(
            &derive_epoch_crs_seed(stmt.epoch, stmt.session_id.as_bytes()),
            &s_i,
        )?;
        let ajtai_bytes = serialize_ajtai_commitment(&ajtai_commitment);

        let sigma_binding = ajtai_sigma_session_binding(
            stmt.session_id.as_bytes(),
            &ajtai_bytes,
            &stmt.ciphertext_bytes,
            &stmt.decrypt_share_bytes,
        );

        let sigma_stmt = SigmaStatement {
            c_rns,
            d_rns: d_rns.clone(),
        };
        let sigma_wit = SigmaWitness {
            s_i: s_i.clone(),
            e_i,
        };
        // G1 Option B: produce 90-round sigma proof for 142-bit soundness.
        let sigma_multi = sigma::prove_multi(
            &sigma_binding,
            u32::from(stmt.participant_id),
            &sigma_stmt,
            &sigma_wit,
            rng,
            &stmt.pvss_commitment,
            sigma::SIGMA_REPETITIONS,
        )?;

        let proof_bytes = encode_proof_multi(
            &ccs_id,
            &ajtai_commitment,
            stmt,
            &stmt.pvss_commitment,
            &d_rns,
            &sigma_multi,
        )?;

        Ok(NizkProof {
            backend_id: BACKEND_ID.to_owned(),
            proof_bytes,
        })
    }

    fn verify(&self, stmt: &NizkStatement, proof: &NizkProof) -> Result<(), NizkError> {
        validate_statement(stmt).inspect_err(|e| {
            eprintln!(
                "PVSS adapter validate_statement failed: {e:?} | stmt.session_id={:?} stmt.params={:?}",
                stmt.session_id, stmt.params
            );
        })?;
        if proof.backend_id != BACKEND_ID {
            return Err(NizkError::VerificationFailed("unexpected proof backend"));
        }
        if proof.proof_bytes.len() > MAX_PROOF_BYTES {
            return Err(NizkError::InvalidInput("proof too large"));
        }

        let mut cur = Cursor::new(&proof.proof_bytes);

        let version = cur.read_u16()?;
        if version != PROOF_VERSION {
            return Err(NizkError::InvalidProof("unsupported proof version"));
        }

        let ccs_id: [u8; 32] = cur
            .read_exact(32)?
            .try_into()
            .map_err(|_| NizkError::InvalidProof("bad ccs_instance_id"))?;

        let expected_ccs_id = compute_ccs_instance_id(stmt)?;
        if ccs_id != expected_ccs_id {
            return Err(NizkError::VerificationFailed("ccs_instance_id mismatch"));
        }

        let ajtai_commitment_bytes = cur.read_exact(26_624)?.to_vec();

        // P1.1: Verify algebraic structure of the Ajtai commitment.
        verify_ajtai_commitment(&ajtai_commitment_bytes)?;

        let session_id_encoded = cur.read_len_prefixed_bytes()?;
        let encoded_pid = cur.read_u16()?;
        let encoded_commitment: [u8; 32] = cur
            .read_exact(32)?
            .try_into()
            .map_err(|_| NizkError::InvalidProof("bad sha256_binding commitment"))?;

        if session_id_encoded != stmt.session_id.as_bytes() {
            return Err(NizkError::VerificationFailed("session_id mismatch"));
        }
        if encoded_pid != stmt.participant_id {
            return Err(NizkError::VerificationFailed("participant_id mismatch"));
        }

        let sigma_section_len = usize::try_from(cur.read_u32()?)
            .map_err(|_| NizkError::InvalidProof("sigma_section_len overflow"))?;
        let sigma_section = cur.read_exact(sigma_section_len)?.to_vec();

        let acc_len = usize::try_from(cur.read_u32()?)
            .map_err(|_| NizkError::InvalidProof("acc_len overflow"))?;
        if acc_len > 0 {
            let acc_bytes = cur.read_exact(acc_len)?.to_vec();
            verify_accumulator_transcript(stmt, &acc_bytes, &ajtai_commitment_bytes)?;
        }

        cur.finish()?;

        let (d_rns, sigma_multi) = decode_sigma_section_multi(&sigma_section)?;

        let c_rns = expand_c_rns(&ccs_id)?;
        let sigma_stmt = SigmaStatement { c_rns, d_rns };

        let sigma_binding = ajtai_sigma_session_binding(
            stmt.session_id.as_bytes(),
            &ajtai_commitment_bytes,
            &stmt.ciphertext_bytes,
            &stmt.decrypt_share_bytes,
        );

        sigma::verify_multi(
            &sigma_binding,
            u32::from(stmt.participant_id),
            &sigma_stmt,
            &sigma_multi,
            &stmt.pvss_commitment,
        )?;

        if !bool::from(encoded_commitment.ct_eq(&stmt.pvss_commitment)) {
            return Err(NizkError::VerificationFailed(
                "pvss_commitment hash binding mismatch",
            ));
        }

        Ok(())
    }

    fn batch_verify(&self, stmts: &[NizkStatement], proofs: &[NizkProof]) -> Result<(), NizkError> {
        if stmts.len() != proofs.len() {
            return Err(NizkError::InvalidInput(
                "statement/proof batch length mismatch",
            ));
        }
        if stmts.len() > MAX_BATCH_STMTS {
            return Err(NizkError::InvalidInput(
                "batch_verify participant count exceeds maximum",
            ));
        }
        for (s, p) in stmts.iter().zip(proofs.iter()) {
            self.verify(s, p)?;
        }
        Ok(())
    }
}

/// Public extraction of sigma proof internals from opaque proof bytes.
///
/// Returns `(d_rns, SigmaProof { t_rns, z_s, z_e, ch })` by parsing
/// the sigma section from the encoded proof.
pub fn extract_sigma_proof(proof_bytes: &[u8]) -> Result<(Vec<u64>, sigma::SigmaProof), NizkError> {
    let mut cur = Cursor::new(proof_bytes);

    let version = cur.read_u16()?;
    if version != PROOF_VERSION {
        return Err(NizkError::InvalidProof("unsupported proof version"));
    }

    cur.skip(32)?; // ccs_instance_id
    cur.skip(26_624)?; // ajtai_commitment

    let _sid = cur.read_len_prefixed_bytes()?;
    let _pid = cur.read_u16()?;
    let _commitment: [u8; 32] = cur
        .read_exact(32)?
        .try_into()
        .map_err(|_| NizkError::InvalidProof("bad sha256_binding commitment"))?;

    let sigma_section_len = usize::try_from(cur.read_u32()?)
        .map_err(|_| NizkError::InvalidProof("sigma_section_len overflow"))?;
    let sigma_section = cur.read_exact(sigma_section_len)?.to_vec();

    let (d_rns, multi_proof) = decode_sigma_section_multi(&sigma_section)?;
    let first_round = multi_proof
        .rounds
        .into_iter()
        .next()
        .ok_or(NizkError::InvalidProof("sigma multi-proof has zero rounds"))?;
    Ok((d_rns, first_round))
}

/// Public extraction of the full sigma verifier input from opaque proof bytes.
///
/// Returns `(c_rns, d_rns, SigmaProof)` where `c_rns` is the deterministic
/// statement polynomial derived from the encoded CCS instance id and `d_rns`
/// is the proof-embedded decrypt-share polynomial used by the sigma verifier.
/// Returns a `SigmaMultiProof` with all 90 parallel repetition rounds (G1 Option B).
pub fn extract_sigma_statement_and_proof(
    stmt: &NizkStatement,
    proof_bytes: &[u8],
) -> Result<(Vec<u64>, Vec<u64>, sigma::SigmaMultiProof), NizkError> {
    validate_statement(stmt)?;
    let mut cur = Cursor::new(proof_bytes);

    let version = cur.read_u16()?;
    if version != PROOF_VERSION {
        return Err(NizkError::InvalidProof("unsupported proof version"));
    }

    let ccs_id: [u8; 32] = cur
        .read_exact(32)?
        .try_into()
        .map_err(|_| NizkError::InvalidProof("bad ccs_instance_id"))?;
    let expected_ccs_id = compute_ccs_instance_id(stmt)?;
    if ccs_id != expected_ccs_id {
        return Err(NizkError::VerificationFailed("ccs_instance_id mismatch"));
    }

    cur.skip(26_624)?; // ajtai_commitment
    let _sid = cur.read_len_prefixed_bytes()?;
    let _pid = cur.read_u16()?;
    let _commitment: [u8; 32] = cur
        .read_exact(32)?
        .try_into()
        .map_err(|_| NizkError::InvalidProof("bad sha256_binding commitment"))?;

    let sigma_section_len = usize::try_from(cur.read_u32()?)
        .map_err(|_| NizkError::InvalidProof("sigma_section_len overflow"))?;
    let sigma_section = cur.read_exact(sigma_section_len)?.to_vec();
    let (d_rns, sigma_multi) = decode_sigma_section_multi(&sigma_section)?;
    let c_rns = expand_c_rns(&ccs_id)?;

    Ok((c_rns, d_rns, sigma_multi))
}

fn validate_statement(stmt: &NizkStatement) -> Result<(), NizkError> {
    if stmt.params.0 == 0 {
        return Err(NizkError::InvalidInput("q must be non-zero"));
    }
    if stmt.params.1 == 0 {
        return Err(NizkError::InvalidInput("ring degree must be non-zero"));
    }
    if stmt.params.1 != rlwe_n() {
        return Err(NizkError::InvalidInput(
            "ring degree must match active preset N",
        ));
    }
    if stmt.session_id.is_empty() {
        return Err(NizkError::InvalidInput("session_id must be non-empty"));
    }
    if stmt.session_id.len() > MAX_SESSION_ID_LEN {
        return Err(NizkError::InvalidInput("session_id too long"));
    }
    if stmt.ciphertext_bytes.is_empty() {
        return Err(NizkError::InvalidInput(
            "ciphertext bytes must be non-empty",
        ));
    }
    if stmt.ciphertext_bytes.len() > MAX_INPUT_BYTES {
        return Err(NizkError::InvalidInput("ciphertext bytes too large"));
    }
    if stmt.decrypt_share_bytes.is_empty() {
        return Err(NizkError::InvalidInput(
            "decrypt-share bytes must be non-empty",
        ));
    }
    if stmt.decrypt_share_bytes.len() > MAX_INPUT_BYTES {
        return Err(NizkError::InvalidInput("decrypt-share bytes too large"));
    }
    Ok(())
}

fn validate_witness(witness: &NizkWitness) -> Result<(), NizkError> {
    if witness.secret_share_poly.is_empty() {
        return Err(NizkError::InvalidInput(
            "secret_share_poly must be non-empty",
        ));
    }
    Ok(())
}

fn verify_accumulator_transcript(
    stmt: &NizkStatement,
    acc_bytes: &[u8],
    _ajtai_commitment_bytes: &[u8],
) -> Result<(), NizkError> {
    let (acc, instance_refs) = accumulator_codec::decode_accumulator(acc_bytes)
        .map_err(|_e| NizkError::VerificationFailed("accumulator transcript decode failed"))?;

    if acc.session_id != stmt.session_id {
        return Err(NizkError::VerificationFailed(
            "accumulator transcript: session_id mismatch",
        ));
    }

    let expected_digest = accumulator_codec::params_digest();
    if acc.params_digest != expected_digest {
        return Err(NizkError::VerificationFailed(
            "accumulator transcript: params_digest mismatch",
        ));
    }

    if acc.norm_bound_current > PVTHFHE_CYCLO_PARAMS.beta_at_t {
        return Err(NizkError::VerificationFailed(
            "accumulator transcript: norm_bound_current exceeds beta_at_t",
        ));
    }

    if acc.fold_depth > PVTHFHE_CYCLO_PARAMS.sequential_t {
        return Err(NizkError::VerificationFailed(
            "accumulator transcript: fold_depth exceeds sequential_t",
        ));
    }

    if acc.acc_commitment_bytes.len() != AJTAI_COMMITMENT_BYTES {
        return Err(NizkError::VerificationFailed(
            "accumulator transcript: commitment length mismatch",
        ));
    }

    if acc.acc_public_io_bytes.len() != 32 {
        return Err(NizkError::VerificationFailed(
            "accumulator transcript: public_io length mismatch",
        ));
    }

    let instance_count = instance_refs.len();
    if acc.fold_depth as usize != instance_count {
        return Err(NizkError::VerificationFailed(
            "accumulator transcript: fold_depth != instance_count",
        ));
    }

    let found_current_participant = instance_refs
        .iter()
        .any(|ir| ir.participant_id == stmt.participant_id);
    if !found_current_participant {
        return Err(NizkError::VerificationFailed(
            "accumulator transcript: current participant_id not found in instance list",
        ));
    }

    for ir in &instance_refs {
        if ir.participant_id == stmt.participant_id {
            let expected_ajtai_hash: [u8; 32] = Sha256::new()
                .chain_update(_ajtai_commitment_bytes)
                .finalize()
                .into();
            if ir.ajtai_commitment_hash != expected_ajtai_hash {
                return Err(NizkError::VerificationFailed(
                    "accumulator transcript: ajtai_commitment_hash mismatch for current participant",
                ));
            }
        }
    }

    Ok(())
}

/// Derive the CCS instance identifier from the statement.
///
/// ccs_instance_id = SHA256(session_id || participant_id u16 BE
///                          || q u64 BE || degree u64 BE || error_bound u64 BE
///                          || b"cyclo-ajtai-d2/v1")
///
/// Including all statement parameters ensures the instance ID is unique per
/// (session, participant, parameter-set) tuple and prevents cross-parameter replay.
fn compute_ccs_instance_id(stmt: &NizkStatement) -> Result<[u8; 32], NizkError> {
    let mut h = Sha256::new();
    h.update(stmt.session_id.as_bytes());
    h.update(stmt.participant_id.to_be_bytes());
    h.update(stmt.params.0.to_be_bytes());
    let degree_u64 = u64::try_from(stmt.params.1)
        .map_err(|_| NizkError::InvalidInput("degree overflows u64"))?;
    h.update(degree_u64.to_be_bytes());
    h.update(stmt.params.2.to_be_bytes());
    h.update(b"cyclo-ajtai-d2/v1");
    Ok(h.finalize().into())
}

/// Expand a 32-byte seed into a uniform RLWE polynomial `c` in RNS power-basis form.
///
/// Seed derivation: `ChaCha20Rng::from_seed(ccs_instance_id)` with rejection
/// sampling per limb to avoid modular bias.
fn expand_c_rns(seed: &[u8; 32]) -> Result<Vec<u64>, NizkError> {
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let moduli = pvthfhe_types::rlwe_moduli();
    let n = rlwe_n();
    let mut c_rns = vec![0u64; n * moduli.len()];
    for (limb, &q) in moduli.iter().enumerate() {
        let threshold = u64::MAX - (u64::MAX % q);
        for j in 0..rlwe_n() {
            loop {
                let v = rng.next_u64();
                if v < threshold {
                    c_rns[limb * rlwe_n() + j] = v % q;
                    break;
                }
            }
        }
    }
    Ok(c_rns)
}

fn pad_or_truncate_to_rlwe_n(v: &[i64]) -> Vec<i64> {
    let mut out = vec![0i64; rlwe_n()];
    let take = v.len().min(rlwe_n());
    out[..take].copy_from_slice(&v[..take]);
    out
}

/// Verify the algebraic structure of a deserialized Ajtai commitment.
///
/// Checks that:
/// 1. The commitment contains exactly AJTAI_RANK (13) ring elements
/// 2. Each element's coefficients are within the valid centred range (-Q_COMMIT/2, Q_COMMIT/2]
///
/// This is a structural validation, not a full opening check (the verifier does not
/// hold the witness s).  Combined with the sigma proof, this ensures the commitment
/// is well-formed and bound to the sigma transcript.
fn verify_ajtai_commitment(bytes: &[u8]) -> Result<(), NizkError> {
    if bytes.len() != 26_624 {
        return Err(NizkError::InvalidProof(
            "ajtai commitment: wrong byte length",
        ));
    }

    let expected_elems = AJTAI_RANK; // a = 13
    let coeffs_per_elem = PHI; // φ = 256
    let bytes_per_elem = coeffs_per_elem * 8; // 2048 bytes/element

    let half_q = (Q_COMMIT / 2) as i64;

    for (elem_idx, chunk) in bytes.chunks(bytes_per_elem).enumerate() {
        if elem_idx >= expected_elems {
            return Err(NizkError::InvalidProof(
                "ajtai commitment: too many ring elements",
            ));
        }
        if chunk.len() != bytes_per_elem {
            return Err(NizkError::InvalidProof(
                "ajtai commitment: truncated ring element",
            ));
        }
        for coeff_idx in (0..coeffs_per_elem).map(|j| j * 8) {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&chunk[coeff_idx..coeff_idx + 8]);
            let coeff = i64::from_le_bytes(buf);
            // Coefficients must be in centred range (-Q_COMMIT/2, Q_COMMIT/2]
            if coeff <= -half_q || coeff > half_q {
                return Err(NizkError::InvalidProof(
                    "ajtai commitment: coefficient out of range",
                ));
            }
        }
    }

    Ok(())
}

/// Deserialize an Ajtai commitment from its canonical byte representation.
#[allow(dead_code)]
fn deserialize_ajtai_commitment(bytes: &[u8]) -> Result<AjtaiCommitment, NizkError> {
    if bytes.len() != 26_624 {
        return Err(NizkError::InvalidProof(
            "ajtai commitment: wrong byte length",
        ));
    }

    let mut elems = Vec::with_capacity(AJTAI_RANK);
    let coeffs_per_elem = PHI;
    let bytes_per_elem = coeffs_per_elem * 8;

    for chunk in bytes.chunks(bytes_per_elem) {
        if chunk.len() != bytes_per_elem {
            return Err(NizkError::InvalidProof(
                "ajtai commitment: truncated ring element",
            ));
        }
        let mut coeffs = [0i64; PHI];
        for (j, c) in coeffs.iter_mut().enumerate() {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&chunk[j * 8..(j + 1) * 8]);
            *c = i64::from_le_bytes(buf);
        }
        elems.push(Rq::new(coeffs, Q_COMMIT));
    }

    Ok(AjtaiCommitment { elems })
}

fn ajtai_sigma_session_binding(
    session_id: &[u8],
    ajtai_bytes: &[u8],
    ciphertext_bytes: &[u8],
    decrypt_share_bytes: &[u8],
) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(session_id);
    h.update(ajtai_bytes);
    h.update(ciphertext_bytes);
    h.update(decrypt_share_bytes);
    h.finalize().to_vec()
}

fn serialize_ajtai_commitment(ajtai: &AjtaiCommitment) -> Vec<u8> {
    let mut out = Vec::with_capacity(26_624);
    for elem in &ajtai.elems {
        for &c in &elem.coeffs {
            out.extend_from_slice(&c.to_le_bytes());
        }
    }
    out
}

fn derive_epoch_crs_seed(epoch: u64, session_id: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(epoch.to_be_bytes());
    h.update(b"pvthfhe-ajtai-crs/v1");
    h.update(session_id);
    h.finalize().into()
}

fn compute_ajtai_commitment(
    crs_seed: &[u8; 32],
    s_i: &[i64],
) -> Result<AjtaiCommitment, NizkError> {
    let params = AjtaiParams::default();
    let matrix = AjtaiMatrix::from_seed(*crs_seed, &params, ajtai_m())?; // allow-seeded-rng: CRS seed is epoch-bound
    let witness_rq: Vec<Rq> = s_i
        .chunks(PHI)
        .map(|chunk| {
            let mut coeffs = [0i64; PHI];
            coeffs[..chunk.len()].copy_from_slice(chunk);
            Rq::new(coeffs, Q_COMMIT)
        })
        .collect();
    AjtaiCommitment::commit(&matrix, &witness_rq)
}

fn encode_u64s_le(out: &mut Vec<u8>, vals: &[u64]) {
    let len = u32::try_from(vals.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    for &v in vals {
        out.extend_from_slice(&v.to_le_bytes());
    }
}

fn encode_i64s_le(out: &mut Vec<u8>, vals: &[i64]) {
    let len = u32::try_from(vals.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    for &v in vals {
        out.extend_from_slice(&v.to_le_bytes());
    }
}

fn encode_proof_multi(
    ccs_id: &[u8; 32],
    ajtai: &AjtaiCommitment,
    stmt: &NizkStatement,
    hash_commitment: &[u8; 32],
    d_rns: &[u64],
    sigma_multi: &sigma::SigmaMultiProof,
) -> Result<Vec<u8>, NizkError> {
    let mut out = Vec::new();

    out.extend_from_slice(&PROOF_VERSION.to_be_bytes());
    out.extend_from_slice(ccs_id);

    for elem in &ajtai.elems {
        for &c in &elem.coeffs {
            out.extend_from_slice(&c.to_le_bytes());
        }
    }

    let sid_bytes = stmt.session_id.as_bytes();
    let sid_len = u32::try_from(sid_bytes.len())
        .map_err(|_| NizkError::InvalidInput("session_id too long"))?;
    out.extend_from_slice(&sid_len.to_be_bytes());
    out.extend_from_slice(sid_bytes);
    out.extend_from_slice(&stmt.participant_id.to_be_bytes());
    out.extend_from_slice(hash_commitment);

    let mut sigma_section = Vec::new();
    encode_u64s_le(&mut sigma_section, d_rns);
    // Encode round count followed by per-round proofs
    let num_rounds = u32::try_from(sigma_multi.rounds.len())
        .map_err(|_| NizkError::InvalidInput("too many sigma rounds"))?;
    sigma_section.extend_from_slice(&num_rounds.to_be_bytes());
    for proof in &sigma_multi.rounds {
        encode_u64s_le(&mut sigma_section, &proof.t_rns);
        encode_i64s_le(&mut sigma_section, &proof.z_s);
        encode_i64s_le(&mut sigma_section, &proof.z_e);
        encode_ch_ternary_32(&mut sigma_section, proof.ch)?;
    }

    let sigma_len = u32::try_from(sigma_section.len())
        .map_err(|_| NizkError::InvalidInput("sigma section too large"))?;
    out.extend_from_slice(&sigma_len.to_be_bytes());
    out.extend_from_slice(&sigma_section);

    // Non-folded placeholder: accumulator transcript verification is
    // provided by append_accumulator_to_proof() for folded proofs.
    out.extend_from_slice(&0u32.to_be_bytes());

    Ok(out)
}

/// Append a versioned Cyclo accumulator transcript to an existing proof.
///
/// Replaces the trailing empty placeholder with the serialized accumulator
/// transcript.  The caller must supply the accumulator and the instance list
/// that was folded into it.
pub fn append_accumulator_to_proof(
    proof_bytes: &mut Vec<u8>,
    acc: &pvthfhe_cyclo::CycloAccumulator,
    instances: &[pvthfhe_cyclo::CcsPShareInstance],
) -> Result<(), NizkError> {
    if proof_bytes.len() < 4 {
        return Err(NizkError::InvalidInput(
            "proof too short for accumulator placeholder",
        ));
    }
    let old_len = proof_bytes.len();
    proof_bytes.truncate(old_len - 4);

    let acc_transcript = accumulator_codec::encode_accumulator(acc, instances)
        .map_err(|_| NizkError::InvalidInput("accumulator transcript encode failed"))?;

    let acc_len = u32::try_from(acc_transcript.len())
        .map_err(|_| NizkError::InvalidInput("accumulator transcript too large"))?;
    proof_bytes.extend_from_slice(&acc_len.to_be_bytes());
    proof_bytes.extend_from_slice(&acc_transcript);
    Ok(())
}

fn decode_sigma_section(bytes: &[u8]) -> Result<(Vec<u64>, sigma::SigmaProof), NizkError> {
    let mut cur = Cursor::new(bytes);
    let d_rns = cur.read_u64s()?;
    let t_rns = cur.read_u64s()?;
    let z_s = cur.read_i64s()?;
    let z_e = cur.read_i64s()?;
    let ch = cur.read_ch_ternary_32()?;
    cur.finish()?;
    Ok((
        d_rns,
        sigma::SigmaProof {
            t_rns,
            z_s,
            z_e,
            ch,
        },
    ))
}

fn decode_sigma_section_multi(
    bytes: &[u8],
) -> Result<(Vec<u64>, sigma::SigmaMultiProof), NizkError> {
    let mut cur = Cursor::new(bytes);
    let d_rns = cur.read_u64s()?;
    let num_rounds = usize::try_from(cur.read_u32()?)
        .map_err(|_| NizkError::InvalidProof("sigma round count overflow"))?;
    let mut rounds = Vec::with_capacity(num_rounds);
    for _ in 0..num_rounds {
        let t_rns = cur.read_u64s()?;
        let z_s = cur.read_i64s()?;
        let z_e = cur.read_i64s()?;
        let ch = cur.read_ch_ternary_32()?;
        rounds.push(sigma::SigmaProof {
            t_rns,
            z_s,
            z_e,
            ch,
        });
    }
    cur.finish()?;
    Ok((d_rns, sigma::SigmaMultiProof { rounds }))
}

fn encode_ch_ternary_32(out: &mut Vec<u8>, ch: i64) -> Result<(), NizkError> {
    let fill = match ch {
        -1 => 0xff,
        0 | 1 => 0x00,
        _ => return Err(NizkError::InvalidInput("challenge must be -1, 0, or 1")),
    };
    let mut encoded = [fill; 32];
    encoded[..8].copy_from_slice(&ch.to_le_bytes());
    out.extend_from_slice(&encoded);
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], NizkError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(NizkError::InvalidProof("proof length overflow"))?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(NizkError::InvalidProof("truncated proof bytes"))?;
        self.offset = end;
        Ok(slice)
    }

    fn skip(&mut self, len: usize) -> Result<(), NizkError> {
        self.read_exact(len)?;
        Ok(())
    }

    fn read_u16(&mut self) -> Result<u16, NizkError> {
        let b: [u8; 2] = self
            .read_exact(2)?
            .try_into()
            .map_err(|_| NizkError::InvalidProof("bad u16"))?;
        Ok(u16::from_be_bytes(b))
    }

    fn read_u32(&mut self) -> Result<u32, NizkError> {
        let b: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| NizkError::InvalidProof("bad u32"))?;
        Ok(u32::from_be_bytes(b))
    }

    fn read_len_prefixed_bytes(&mut self) -> Result<Vec<u8>, NizkError> {
        let len = usize::try_from(self.read_u32()?)
            .map_err(|_| NizkError::InvalidProof("length overflows usize"))?;
        Ok(self.read_exact(len)?.to_vec())
    }

    fn read_u64s(&mut self) -> Result<Vec<u64>, NizkError> {
        let count = usize::try_from(self.read_u32()?)
            .map_err(|_| NizkError::InvalidProof("u64s count overflows usize"))?;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let b: [u8; 8] = self
                .read_exact(8)?
                .try_into()
                .map_err(|_| NizkError::InvalidProof("bad u64"))?;
            out.push(u64::from_le_bytes(b));
        }
        Ok(out)
    }

    fn read_i64s(&mut self) -> Result<Vec<i64>, NizkError> {
        let count = usize::try_from(self.read_u32()?)
            .map_err(|_| NizkError::InvalidProof("i64s count overflows usize"))?;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let b: [u8; 8] = self
                .read_exact(8)?
                .try_into()
                .map_err(|_| NizkError::InvalidProof("bad i64"))?;
            out.push(i64::from_le_bytes(b));
        }
        Ok(out)
    }

    fn read_ch_ternary_32(&mut self) -> Result<i64, NizkError> {
        let bytes = self.read_exact(32)?;
        let low: [u8; 8] = bytes[..8]
            .try_into()
            .map_err(|_| NizkError::InvalidProof("bad challenge scalar"))?;
        let ch = i64::from_le_bytes(low);
        let expected_fill = match ch {
            -1 => 0xff,
            0 | 1 => 0x00,
            _ => return Err(NizkError::InvalidProof("challenge must be -1, 0, or 1")),
        };
        if bytes[8..].iter().any(|&b| b != expected_fill) {
            return Err(NizkError::InvalidProof("non-canonical challenge scalar"));
        }
        Ok(ch)
    }

    fn finish(self) -> Result<(), NizkError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(NizkError::InvalidProof("trailing proof bytes"))
        }
    }
}
