//! Prover side of the share-encryption NIZK: [`ShareNizkProver`], the
//! commitment-ciphertext construction, the share sigma (algebraic) proof, and
//! the self-contained BFV encryption sigma proof.

use fhe_math::rq::Context;
use fhe_traits::DeserializeWithContext;
use pvthfhe_fhe::types::PublicKey;
use pvthfhe_fhe::wire;
use pvthfhe_fhe::FheBackend;
use pvthfhe_foundations::domain_tags::Tag;
use pvthfhe_foundations::types::{EncryptionWitness, ProtocolBytes};
use pvthfhe_nizk::bfv_sigma::{
    self, bfv_delta_rns, encode_bfv_sigma_proof, poly_bytes_to_rns, BfvSigmaStatement,
    BfvSigmaWitness,
};
use pvthfhe_nizk::sigma;
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};

use crate::PvssError;

use super::statement::{
    bfv_sigma_binding_data, compute_commitment_binding, compute_lattice_binding,
    compute_relation_binding, compute_share_d_commitment, derive_challenge,
    derive_share_sigma_c_rns, validate_statement, validate_witness, ShareNizkOpenedProof,
    ShareNizkProof, ShareNizkStatement, ShareNizkWitness,
};
use super::{DIGEST_LEN, SHARE_NIZK_DOMAIN_SEPARATOR};

/// Prover for the share-encryption proof. Requires FHE backend for encryption.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShareNizkProver;

impl ShareNizkProver {
    /// Produce a share-encryption proof.
    ///
    /// The proof does NOT serialize the witness into the proof envelope.
    /// Instead, it creates a commitment ciphertext using the FHE backend
    /// and binds it to the statement via a lattice binding tag.
    ///
    /// For v4, also produces a BFV encryption sigma proof when the backend
    /// supports `encrypt_with_witness`.
    pub fn prove(
        backend: &dyn FheBackend,
        stmt: &ShareNizkStatement,
        witness: &ShareNizkWitness,
        track_domain_tag: Option<&[u8]>,
    ) -> Result<ShareNizkProof, PvssError> {
        validate_statement(stmt)?;
        validate_witness(witness)?;

        let mut fresh_nonce = [0u8; DIGEST_LEN];
        rand::thread_rng().fill_bytes(&mut fresh_nonce);
        let commitment_seed = compute_commitment_seed(stmt, track_domain_tag, &fresh_nonce);

        let commitment_ct = create_commitment_ct(backend, stmt, witness, &commitment_seed)?;

        // ── Algebraic proof (share sigma over RLWE) ──
        let algebraic_proof = build_algebraic_proof(stmt, witness);

        // ── Relation binding ──
        let relation_binding = compute_relation_binding(stmt, &algebraic_proof);

        // ── Commitment binding ──
        let commitment_binding = compute_commitment_binding(stmt, &relation_binding);

        // ── Challenge ──
        let challenge = derive_challenge(stmt, &commitment_ct);

        // ── Lattice binding ──
        let lattice_binding = compute_lattice_binding(
            stmt,
            &commitment_ct,
            &commitment_binding,
            &challenge,
            &relation_binding,
        );

        // ── D2 binding ──
        let mut hasher = Sha256::new();
        hasher.update(&commitment_ct);
        hasher.update(stmt.share_commitment.as_slice());
        hasher.update(stmt.session_id.as_slice());
        hasher.update(stmt.dkg_root.as_slice());
        hasher.update((stmt.recipient_index as u64).to_le_bytes());
        let d2_binding: [u8; 32] = hasher.finalize().into();

        // ── BFV encryption proof (v4) ──
        let bfv_encryption_proof = build_bfv_encryption_proof(backend, stmt, witness)?;

        let opened = ShareNizkOpenedProof {
            statement: stmt.clone(),
            commitment_bytes: ProtocolBytes(commitment_ct),
            commitment_seed,
            commitment_nonce: fresh_nonce,
            commitment_binding,
            challenge,
            lattice_binding,
            relation_binding,
            algebraic_proof: ProtocolBytes(algebraic_proof),
            bfv_encryption_proof,
            d2_binding,
            domain_separator: SHARE_NIZK_DOMAIN_SEPARATOR.to_owned(),
        };

        ShareNizkProof::from_opened(&opened)
    }

    /// Produce a batched share-encryption proof (D.2).
    ///
    /// Creates independent per-track proofs for the sk track and each
    /// e_sm slot, then concatenates them into a single batched proof
    /// envelope. The proof is verified by [`super::ShareNizkBatchedVerifier::verify`].
    pub fn prove_batched(
        backend: &dyn FheBackend,
        batched: &super::ShareNizkBatchedStatement,
        sk_witness: &ShareNizkWitness,
        esm_witnesses: &[ShareNizkWitness],
    ) -> Result<ShareNizkProof, PvssError> {
        let sk_domain_tag = Tag::PvssBatchedDkgShareEncryptionSkTrack.as_bytes();
        let esm_domain_tag = Tag::PvssBatchedDkgShareEncryptionESmTrack.as_bytes();

        // Prove SK track — construct statement from the sk track directly
        let sk_stmt = ShareNizkStatement {
            session_id: batched.session_id.clone(),
            dealer_index: batched.dealer_index,
            recipient_index: batched.recipient_index,
            recipient_pk: batched.recipient_pk.clone(),
            bfv_params_digest: batched.bfv_params_digest.clone(),
            dkg_root: batched.dkg_root.clone(),
            ciphertext_u: batched.sk.ciphertext_u.clone(),
            ciphertext_v: batched.sk.ciphertext_v.clone(),
            share_commitment: batched.sk.track_commitment.clone(),
        };
        let sk_proof = Self::prove(backend, &sk_stmt, sk_witness, Some(sk_domain_tag))?;

        // Prove ESm tracks (construct statements from array positions, not slot_index).
        let mut esm_proofs: Vec<ShareNizkProof> = Vec::with_capacity(esm_witnesses.len());
        for (i, esm_witness) in esm_witnesses.iter().enumerate() {
            let esm_track = &batched.esm_slots[i];
            let esm_stmt = ShareNizkStatement {
                session_id: batched.session_id.clone(),
                dealer_index: batched.dealer_index,
                recipient_index: batched.recipient_index,
                recipient_pk: batched.recipient_pk.clone(),
                bfv_params_digest: batched.bfv_params_digest.clone(),
                dkg_root: batched.dkg_root.clone(),
                ciphertext_u: esm_track.ciphertext_u.clone(),
                ciphertext_v: esm_track.ciphertext_v.clone(),
                share_commitment: esm_track.track_commitment.clone(),
            };
            let esm_proof = Self::prove(backend, &esm_stmt, esm_witness, Some(esm_domain_tag))?;
            esm_proofs.push(esm_proof);
        }

        // Encode batched proof: [num_tracks: u16][sk_proof_len: u32][sk_proof_bytes][esm0_proof_len: u32][esm0_proof_bytes]...
        let num_tracks = 1u16 + esm_proofs.len() as u16;
        let mut out = Vec::new();
        out.extend_from_slice(&num_tracks.to_be_bytes());
        // SK track proof
        let sk_bytes = sk_proof.proof_bytes.as_slice();
        out.extend_from_slice(&(sk_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(sk_bytes);
        // ESm track proofs
        for esm_proof in &esm_proofs {
            let esm_bytes = esm_proof.proof_bytes.as_slice();
            out.extend_from_slice(&(esm_bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(esm_bytes);
        }

        let batched_domain = std::str::from_utf8(Tag::PvssBatchedDkgShareEncryption.as_bytes())
            .map_err(|_| PvssError::InvalidShare {
                party_id: Some(batched.recipient_index as u16),
            })?;
        Ok(ShareNizkProof {
            proof_bytes: ProtocolBytes(out),
            domain_separator: batched_domain.to_owned(),
        })
    }
}

fn compute_commitment_seed(
    stmt: &ShareNizkStatement,
    track_domain_tag: Option<&[u8]>,
    nonce: &[u8; DIGEST_LEN],
) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(b"greco-bfv-commitment-seed-v2");
    hasher.update(stmt.session_id.as_slice());
    hasher.update(stmt.recipient_pk.as_slice());
    hasher.update(stmt.ciphertext_u.as_slice());
    hasher.update(stmt.share_commitment.as_slice());
    if let Some(tag) = track_domain_tag {
        hasher.update(tag);
    }
    hasher.update(nonce);
    hasher.finalize().into()
}

fn create_commitment_ct(
    backend: &dyn FheBackend,
    stmt: &ShareNizkStatement,
    witness: &ShareNizkWitness,
    commitment_seed: &[u8; DIGEST_LEN],
) -> Result<Vec<u8>, PvssError> {
    let pk = PublicKey {
        bytes: stmt.recipient_pk.as_slice().to_vec(),
    };

    let plaintext = witness.share_bytes.expose();

    let mut rng = ChaCha20Rng::from_seed(*commitment_seed); // allow-seeded-rng: deterministic Ajtai commitment binding in PVSS proof

    let ciphertext =
        backend
            .encrypt(&pk, plaintext, &mut rng)
            .map_err(|_| PvssError::InvalidShare {
                party_id: Some(stmt.recipient_index as u16),
            })?;

    Ok(ciphertext.bytes)
}

/// Build algebraic proof: share sigma proof over RLWE relation.
fn build_algebraic_proof(stmt: &ShareNizkStatement, witness: &ShareNizkWitness) -> Vec<u8> {
    let s_i = derive_share_sigma_witness(witness.share_bytes.expose());
    // e_i=0 proves d_i = c*s_i (algebraic binding); full RLWE soundness via BFV sigma proof (v4).
    let e_i = vec![0i64; sigma::rlwe_n()];
    let c_rns = derive_share_sigma_c_rns(stmt.session_id.as_slice(), stmt.recipient_index);
    let d_rns = sigma::compute_d_rns(&c_rns, &s_i, &e_i).unwrap_or_else(|_| {
        vec![0u64; sigma::rlwe_n() * pvthfhe_foundations::types::rlwe_moduli().len()]
    });

    let mut proof_rng = match ChaCha20Rng::from_rng(&mut OsRng) {
        Ok(rng) => rng,
        Err(_) => return vec![],
    };
    let sigma_stmt = sigma::SigmaStatement {
        c_rns,
        d_rns: d_rns.clone(),
    };
    let sigma_witness = sigma::SigmaWitness { s_i, e_i };
    let d_commitment = compute_share_d_commitment(stmt);
    let proof = sigma::prove(
        stmt.session_id.as_slice(),
        u32::try_from(stmt.recipient_index).unwrap_or(0),
        &sigma_stmt,
        &sigma_witness,
        &mut proof_rng,
        &d_commitment,
    );

    match proof {
        Ok(p) => encode_algebraic_proof(&d_rns, &p),
        Err(_) => vec![],
    }
}

fn derive_share_sigma_witness(share: &[u8]) -> Vec<i64> {
    let mut h = Sha256::new();
    h.update(Tag::ShareSigmaWitnessDigest.as_bytes());
    h.update(u64::try_from(share.len()).unwrap_or(0).to_be_bytes());
    h.update(share);
    let digest = h.finalize();
    let mut out = vec![0i64; sigma::rlwe_n()];
    for (byte_index, byte) in digest.iter().enumerate() {
        for bit in 0..8usize {
            let idx = byte_index * 8 + bit;
            if idx < sigma::rlwe_n() {
                out[idx] = i64::from((byte >> bit) & 1);
            }
        }
    }
    out
}

fn encode_algebraic_proof(d_rns: &[u64], proof: &sigma::SigmaProof) -> Vec<u8> {
    let mut out = Vec::new();
    encode_algebraic_u64_vec(&mut out, d_rns);
    encode_algebraic_u64_vec(&mut out, &proof.t_rns);
    encode_algebraic_i64_vec(&mut out, &proof.z_s);
    encode_algebraic_i64_vec(&mut out, &proof.z_e);
    encode_algebraic_i64_vec(&mut out, &[proof.ch]);
    out
}

fn encode_algebraic_u64_vec(out: &mut Vec<u8>, values: &[u64]) {
    out.extend_from_slice(&u32::try_from(values.len()).unwrap_or(0).to_be_bytes());
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

fn encode_algebraic_i64_vec(out: &mut Vec<u8>, values: &[i64]) {
    out.extend_from_slice(&u32::try_from(values.len()).unwrap_or(0).to_be_bytes());
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

// ── BFV encryption proof ─────────────────────────────────────────────────

/// Build the BFV encryption sigma proof from the encryption witness.
///
/// Attempts to extract the encryption witness via `encrypt_with_witness`.
/// If the backend doesn't support witness extraction (e.g., mock backend),
/// returns an empty proof. The verifier will reject empty proofs for v4.
pub fn build_bfv_encryption_proof(
    backend: &dyn FheBackend,
    stmt: &ShareNizkStatement,
    witness: &ShareNizkWitness,
) -> Result<ProtocolBytes, PvssError> {
    let pk = PublicKey {
        bytes: stmt.recipient_pk.as_slice().to_vec(),
    };
    let share = witness.share_bytes.expose();

    // Reconstruct encryption randomness from witness seed
    let randomness = witness.encryption_randomness.expose();
    if randomness.len() < 32 {
        return Ok(ProtocolBytes(vec![]));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&randomness[..32]);
    let mut enc_rng = ChaCha20Rng::from_seed(seed); // allow-seeded-rng: deterministic re-encryption for BFV proof witness

    // Try to get the EncryptionWitness
    let enc_witness = match backend.encrypt_with_witness(&pk, share, &mut enc_rng) {
        Ok((ciphertext, w)) => {
            if ciphertext.bytes.as_slice() != stmt.ciphertext_u.as_slice()
                || w.ciphertext_bytes.as_slice() != stmt.ciphertext_u.as_slice()
            {
                return Err(PvssError::BfvEncryptionProofFailed {
                    party_id: Some(stmt.recipient_index as u16),
                });
            }
            w
        }
        Err(_) => {
            // Fallback: backend doesn't support witness extraction.
            // Re-encrypt without witness and verify ciphertext consistency.
            let mut fallback_rng = ChaCha20Rng::from_seed(seed); // allow-seeded-rng: deterministic fallback re-encryption check
            let ciphertext = backend
                .encrypt(&pk, share, &mut fallback_rng)
                .map_err(|_| PvssError::InvalidShare {
                    party_id: Some(stmt.recipient_index as u16),
                })?;
            if ciphertext.bytes.as_slice() != stmt.ciphertext_u.as_slice() {
                return Err(PvssError::BfvEncryptionProofFailed {
                    party_id: Some(stmt.recipient_index as u16),
                });
            }
            return Ok(ProtocolBytes(vec![]));
        }
    };

    encode_bfv_encryption_proof_from_witness(stmt, share, &enc_witness)
}

/// Encode a self-contained BFV encryption proof from statement + EncryptionWitness.
fn encode_bfv_encryption_proof_from_witness(
    stmt: &ShareNizkStatement,
    plaintext: &[u8],
    enc_witness: &EncryptionWitness,
) -> Result<ProtocolBytes, PvssError> {
    // --- Build BFV sigma statement ---
    let pk_decoded = wire::decode_public_key(stmt.recipient_pk.as_slice()).map_err(|_| {
        PvssError::InvalidShare {
            party_id: Some(stmt.recipient_index as u16),
        }
    })?;
    if enc_witness.recipient_pk0_bytes.as_slice() != pk_decoded.p0.as_slice()
        || enc_witness.recipient_pk1_bytes.as_slice() != pk_decoded.p1.as_slice()
    {
        return Err(PvssError::BfvEncryptionProofFailed {
            party_id: Some(stmt.recipient_index as u16),
        });
    }

    let pk0_rns = poly_bytes_to_rns(&pk_decoded.p0).map_err(|_| PvssError::InvalidShare {
        party_id: Some(stmt.recipient_index as u16),
    })?;
    let pk1_rns = poly_bytes_to_rns(&pk_decoded.p1).map_err(|_| PvssError::InvalidShare {
        party_id: Some(stmt.recipient_index as u16),
    })?;
    let ct0_rns =
        poly_bytes_to_rns(&enc_witness.ct0_poly_bytes).map_err(|_| PvssError::InvalidShare {
            party_id: Some(stmt.recipient_index as u16),
        })?;
    let ct1_rns =
        poly_bytes_to_rns(&enc_witness.ct1_poly_bytes).map_err(|_| PvssError::InvalidShare {
            party_id: Some(stmt.recipient_index as u16),
        })?;
    let t_plain: u64 = 65536;
    let delta_limbs = bfv_delta_rns(t_plain).map_err(|_| PvssError::InvalidShare {
        party_id: Some(stmt.recipient_index as u16),
    })?;

    let bfv_stmt = BfvSigmaStatement {
        pk0_rns: pk0_rns.clone(),
        pk1_rns: pk1_rns.clone(),
        ct0_rns: ct0_rns.clone(),
        ct1_rns: ct1_rns.clone(),
        delta_limbs: delta_limbs.clone(),
        t_plain,
    };

    // --- Build BFV sigma witness ---
    let u = poly_bytes_to_i64(&enc_witness.u_poly_bytes)?;
    let e0 = poly_bytes_to_i64(&enc_witness.e0_poly_bytes)?;
    let e1 = poly_bytes_to_i64(&enc_witness.e1_poly_bytes)?;
    let m = encode_fhers_plaintext_slots(plaintext)?;

    let bfv_wit = BfvSigmaWitness { u, e0, e1, m };

    // --- Produce sigma proof ---
    let mut proof_rng = ChaCha20Rng::from_rng(&mut OsRng).map_err(|_| PvssError::InvalidShare {
        party_id: Some(stmt.recipient_index as u16),
    })?;
    let d_commitment = compute_share_d_commitment(stmt);
    let binding_data = bfv_sigma_binding_data(stmt, &d_commitment);
    let proof = bfv_sigma::prove(
        stmt.session_id.as_slice(),
        stmt.dealer_index as u32,
        &bfv_stmt,
        &bfv_wit,
        &binding_data,
        &mut proof_rng,
    )
    .map_err(|_| PvssError::InvalidShare {
        party_id: Some(stmt.recipient_index as u16),
    })?;

    let encoded_proof = encode_bfv_sigma_proof(&proof);

    // --- Encode self-contained proof: [t_plain][delta_limbs][pk0_rns][pk1_rns][ct0_rns][ct1_rns][proof] ---
    let mut out = Vec::new();
    // t_plain (u64 LE)
    out.extend_from_slice(&t_plain.to_le_bytes());
    // delta_limbs (3 u64 values)
    for v in &delta_limbs {
        out.extend_from_slice(&v.to_le_bytes());
    }
    // pk0_rns
    out.extend_from_slice(&u32::to_be_bytes(pk0_rns.len() as u32));
    for v in &pk0_rns {
        out.extend_from_slice(&v.to_le_bytes());
    }
    // pk1_rns
    out.extend_from_slice(&u32::to_be_bytes(pk1_rns.len() as u32));
    for v in &pk1_rns {
        out.extend_from_slice(&v.to_le_bytes());
    }
    // ct0_rns
    out.extend_from_slice(&u32::to_be_bytes(ct0_rns.len() as u32));
    for v in &ct0_rns {
        out.extend_from_slice(&v.to_le_bytes());
    }
    // ct1_rns
    out.extend_from_slice(&u32::to_be_bytes(ct1_rns.len() as u32));
    for v in &ct1_rns {
        out.extend_from_slice(&v.to_le_bytes());
    }
    // BfvSigmaProof
    out.extend_from_slice(&encoded_proof);

    Ok(ProtocolBytes(out))
}

fn encode_fhers_plaintext_slots(plaintext: &[u8]) -> Result<Vec<i64>, PvssError> {
    let max = sigma::rlwe_n().saturating_sub(1) * 2;
    if plaintext.len() > max {
        return Err(PvssError::InvalidShare { party_id: None });
    }

    let t_plain: i64 = 65536;
    let t_half: u64 = 32768;
    let mut out = vec![0i64; sigma::rlwe_n()];
    out[0] =
        i64::try_from(plaintext.len()).map_err(|_| PvssError::InvalidShare { party_id: None })?;
    for (slot_index, chunk) in plaintext.chunks(2).enumerate() {
        let lo = u16::from(chunk[0]);
        let hi = chunk.get(1).copied().map(u16::from).unwrap_or(0) << 8;
        let raw = u64::from(lo | hi);
        // BFV Encoding::poly() centers values: v ∈ [0, t) → v if v < t/2 else v - t
        let centered = if raw >= t_half {
            -(t_plain - raw as i64)
        } else {
            i64::try_from(raw).unwrap_or(0)
        };
        out[slot_index + 1] = centered;
    }
    Ok(out)
}

// ── RLWE context (cached, shared by helpers) ──────────────────────────────

fn get_rlwe_context() -> Result<&'static Arc<Context>, PvssError> {
    static CTX: OnceLock<Result<Arc<Context>, String>> = OnceLock::new();
    CTX.get_or_init(|| {
        let moduli = pvthfhe_foundations::types::rlwe_moduli();
        Context::new(&moduli, sigma::rlwe_n())
            .map(Arc::new)
            .map_err(|e| format!("{e:?}"))
    })
    .as_ref()
    .map_err(|_| PvssError::LatticeBindingVerificationFailed { party_id: None })
}

/// Convert poly_bytes (serialized fhe-math `Poly`) to i64 coefficient vector.
///
/// Deserializes the Poly, converts to power basis, and extracts the limb-0
/// coefficients centered around 0.
fn poly_bytes_to_i64(poly_bytes: &[u8]) -> Result<Vec<i64>, PvssError> {
    use fhe_math::rq::{Poly, Representation};

    let ctx = get_rlwe_context()?;

    let mut poly = Poly::from_bytes(poly_bytes, ctx)
        .map_err(|_| PvssError::InvalidShare { party_id: None })?;
    poly.change_representation(Representation::PowerBasis);

    let q0 = i64::try_from(ctx.q[0].modulus())
        .map_err(|_| PvssError::InvalidShare { party_id: None })?;
    let half_q0 = q0 / 2;

    let rns: Vec<u64> = Vec::<u64>::from(&poly);
    let n = sigma::rlwe_n();
    let mut out = Vec::with_capacity(n);
    for &c in rns.iter().take(n) {
        let c = i64::try_from(c).map_err(|_| PvssError::InvalidShare { party_id: None })?;
        out.push(if c > half_q0 { c - q0 } else { c });
    }
    Ok(out)
}
