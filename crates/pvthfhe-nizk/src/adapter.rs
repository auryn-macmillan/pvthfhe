//! `CycloNizkAdapter`: wires the Cyclo-companion Ajtai D2 NIZK backend.
//!
//! # Proof byte layout (spec §3.4 + SPEC EXTENSION for sigma_proof_bytes)
//!
//! ```text
//! version                  : u16 BE = 0x0001
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
//!   ch                     : u32 BE count + count × i64 LE
//! cyclo_accumulator_bytes  : u32 BE length=0 (Phase-2 placeholder)
//! ```
//!
//! # SPEC EXTENSION note
//!
//! `sigma_proof_bytes` (including the embedded `d_rns`) is NOT present in spec
//! §3.4 as of the current revision.  The field was added because sigma::verify
//! requires a `SigmaStatement` containing `d_rns`, which the verifier cannot
//! derive without the witness.  Flag to Prometheus for spec §3.4 update.
//!
//! # Phase 2 Placeholder
//! Phase 2 (F-series): `cyclo_accumulator_bytes` will be populated with real Cyclo fold transcript bytes.

use crate::ajtai::{AjtaiCommitment, AjtaiMatrix, AjtaiParams, Rq, PHI, Q_COMMIT};
use crate::sigma::{self, SigmaStatement, SigmaWitness, RLWE_N};
use crate::{NizkAdapter, NizkError, NizkProof, NizkStatement, NizkWitness, BACKEND_ID};

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const PROOF_VERSION: u16 = 0x0001;

/// Maximum allowed proof byte length (prevents heap-exhaustion from crafted proof).
const MAX_PROOF_BYTES: usize = 1_048_576; // 1 MiB

/// Maximum ciphertext/share byte length.
const MAX_INPUT_BYTES: usize = 1_048_576; // 1 MiB

/// Maximum session_id length in bytes.
const MAX_SESSION_ID_LEN: usize = 256;

/// Maximum number of participants in a batch_verify call.
const MAX_BATCH_STMTS: usize = 1024;

/// Number of `Rq` elements (PHI=256 each) needed to pack RLWE_N coefficients.
const AJTAI_M: usize = RLWE_N / PHI;

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

        let ajtai_commitment = compute_ajtai_commitment(&ccs_id, &s_i)?;
        let ajtai_bytes = serialize_ajtai_commitment(&ajtai_commitment);

        let sigma_binding = ajtai_sigma_session_binding(stmt.session_id.as_bytes(), &ajtai_bytes);

        let sigma_stmt = SigmaStatement {
            c_rns,
            d_rns: d_rns.clone(),
        };
        let sigma_wit = SigmaWitness {
            s_i: s_i.clone(),
            e_i,
        };
        let sigma_proof = sigma::prove(
            &sigma_binding,
            u32::from(stmt.participant_id),
            &sigma_stmt,
            &sigma_wit,
            &stmt.pvss_commitment,
            rng,
        )?;

        let proof_bytes = encode_proof(
            &ccs_id,
            &ajtai_commitment,
            stmt,
            &stmt.pvss_commitment,
            &d_rns,
            &sigma_proof,
        )?;

        Ok(NizkProof {
            backend_id: BACKEND_ID.to_owned(),
            proof_bytes,
        })
    }

    fn verify(&self, stmt: &NizkStatement, proof: &NizkProof) -> Result<(), NizkError> {
        validate_statement(stmt)?;
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

        let session_id_encoded = cur.read_len_prefixed_bytes()?;
        let encoded_pid = cur.read_u16()?;
        let encoded_commitment: [u8; 32] = cur
            .read_exact(32)?
            .try_into()
            .map_err(|_| NizkError::InvalidProof("bad sha256_binding commitment"))?;

        let _ = session_id_encoded;
        let _ = encoded_pid;

        let sigma_section_len = usize::try_from(cur.read_u32()?)
            .map_err(|_| NizkError::InvalidProof("sigma_section_len overflow"))?;
        let sigma_section = cur.read_exact(sigma_section_len)?.to_vec();

        let acc_len = usize::try_from(cur.read_u32()?)
            .map_err(|_| NizkError::InvalidProof("acc_len overflow"))?;
        cur.skip(acc_len)?;

        cur.finish()?;

        let (d_rns, sigma_proof) = decode_sigma_section(&sigma_section)?;

        let c_rns = expand_c_rns(&ccs_id)?;
        let sigma_stmt = SigmaStatement { c_rns, d_rns };

        let sigma_binding =
            ajtai_sigma_session_binding(stmt.session_id.as_bytes(), &ajtai_commitment_bytes);

        sigma::verify(
            &sigma_binding,
            u32::from(stmt.participant_id),
            &sigma_stmt,
            &sigma_proof,
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

fn validate_statement(stmt: &NizkStatement) -> Result<(), NizkError> {
    if stmt.params.0 == 0 {
        return Err(NizkError::InvalidInput("q must be non-zero"));
    }
    if stmt.params.1 == 0 {
        return Err(NizkError::InvalidInput("ring degree must be non-zero"));
    }
    if stmt.params.1 != RLWE_N {
        return Err(NizkError::InvalidInput(
            "ring degree must equal RLWE_N=8192",
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
    use crate::sigma::{RLWE_Q0, RLWE_Q1, RLWE_Q2};
    let mut rng = ChaCha20Rng::from_seed(*seed); // allow-seeded-rng: deterministic NIZK test vector generation
    const MODULI: [u64; 3] = [RLWE_Q0, RLWE_Q1, RLWE_Q2];
    let mut c_rns = vec![0u64; RLWE_N * 3];
    for (limb, &q) in MODULI.iter().enumerate() {
        let threshold = u64::MAX - (u64::MAX % q);
        for j in 0..RLWE_N {
            loop {
                let v = rng.next_u64();
                if v < threshold {
                    c_rns[limb * RLWE_N + j] = v % q;
                    break;
                }
            }
        }
    }
    Ok(c_rns)
}

fn pad_or_truncate_to_rlwe_n(v: &[i64]) -> Vec<i64> {
    let mut out = vec![0i64; RLWE_N];
    let take = v.len().min(RLWE_N);
    out[..take].copy_from_slice(&v[..take]);
    out
}

fn ajtai_sigma_session_binding(session_id: &[u8], ajtai_bytes: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(session_id);
    h.update(ajtai_bytes);
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

fn compute_ajtai_commitment(ccs_id: &[u8; 32], s_i: &[i64]) -> Result<AjtaiCommitment, NizkError> {
    let params = AjtaiParams::default();
    let matrix = AjtaiMatrix::from_seed(*ccs_id, &params, AJTAI_M)?; // allow-seeded-rng: CCS matrix seeded from canonical instance id
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

fn encode_proof(
    ccs_id: &[u8; 32],
    ajtai: &AjtaiCommitment,
    stmt: &NizkStatement,
    hash_commitment: &[u8; 32],
    d_rns: &[u64],
    sigma_proof: &sigma::SigmaProof,
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
    encode_u64s_le(&mut sigma_section, &sigma_proof.t_rns);
    encode_i64s_le(&mut sigma_section, &sigma_proof.z_s);
    encode_i64s_le(&mut sigma_section, &sigma_proof.z_e);
    encode_i64s_le(&mut sigma_section, &sigma_proof.ch);

    let sigma_len = u32::try_from(sigma_section.len())
        .map_err(|_| NizkError::InvalidInput("sigma section too large"))?;
    out.extend_from_slice(&sigma_len.to_be_bytes());
    out.extend_from_slice(&sigma_section);

    // Phase 2 (F-series): populate with real Cyclo fold transcript bytes.
    out.extend_from_slice(&0u32.to_be_bytes());

    Ok(out)
}

fn decode_sigma_section(bytes: &[u8]) -> Result<(Vec<u64>, sigma::SigmaProof), NizkError> {
    let mut cur = Cursor::new(bytes);
    let d_rns = cur.read_u64s()?;
    let t_rns = cur.read_u64s()?;
    let z_s = cur.read_i64s()?;
    let z_e = cur.read_i64s()?;
    let ch = cur.read_i64s()?;
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

    fn finish(self) -> Result<(), NizkError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(NizkError::InvalidProof("trailing proof bytes"))
        }
    }
}
