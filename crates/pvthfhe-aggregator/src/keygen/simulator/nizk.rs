//! Keygen and encrypted-share NIZK proving: BFV keypair-correctness sigma
//! proofs (C0), per-recipient Cyclo NIZKs, and the simulator's deterministic
//! witness/error polynomial derivation.

use super::super::types::PartyId;
use super::{hash_bytes, KeygenSimulator};
use pvthfhe_fhe::{Ciphertext, PublicKey};
use pvthfhe_foundations::domain_tags::Tag;
use pvthfhe_nizk::adapter::CycloNizkAdapter;
use pvthfhe_nizk::bfv_sigma::poly_bytes_to_rns;
use pvthfhe_nizk::sigma::{self, SigmaStatement, SigmaWitness};
use pvthfhe_nizk::{NizkAdapter, NizkStatement, NizkWitness};
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};

impl KeygenSimulator {
    pub(super) fn prove_keygen_nizk(
        &self,
        session_id: &[u8; 32],
        dealer_id: PartyId,
        recipient_id: PartyId,
        ct: &Ciphertext,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, pvthfhe_nizk::NizkError> {
        // Delegate to the existing CycloNizkAdapter flow for per-recipient NIZKs.
        self._prove_share_nizk(session_id, dealer_id, recipient_id, ct, plaintext)
    }

    pub(super) fn generate_keygen_nizk(
        &self,
        session_id: &[u8; 32],
        party_id: PartyId,
        pk_i: &PublicKey,
        share: &pvthfhe_fhe::KeygenShare,
    ) -> Result<Vec<u8>, String> {
        let real_pk = self
            .backend
            .aggregate_keygen(&[share.clone()])
            .map_err(|e| format!("aggregate single keygen: {e}"))?;
        let (pk0_bytes, pk1_bytes) = self
            .backend
            .decode_pk_polys(&real_pk)
            .map_err(|e| format!("decode pk polys: {e}"))?;

        let (sk_coeffs, error_bytes) = self
            .backend
            .keygen_witness(party_id)
            .map_err(|e| format!("keygen witness: {e}"))?
            .ok_or_else(|| "no keygen witness for party".to_string())?;

        let c_rns = poly_bytes_to_rns(&pk1_bytes).map_err(|e| format!("pk1 rns: {e}"))?;
        let d_rns = poly_bytes_to_rns(&pk0_bytes).map_err(|e| format!("pk0 rns: {e}"))?;

        let mut rng = ChaCha8Rng::from_seed( // allow-seeded-rng: deterministic simulator
            *Sha256::digest(format!("keygen-nizk-rng-{party_id}").as_bytes()).as_ref(),
        );

        let error_rns = poly_bytes_to_rns(&error_bytes).map_err(|e| format!("error rns: {e}"))?;
        let n = pvthfhe_nizk::sigma::rlwe_n();
        let q0 = 288230376173076481u64;
        let e_coeffs: Vec<i64> = error_rns
            .iter()
            .take(n)
            .map(|&v| {
                if v > q0 / 2 {
                    (v as i128 - q0 as i128) as i64
                } else {
                    v as i64
                }
            })
            .collect();

        let stmt = SigmaStatement { c_rns, d_rns };
        let wit = SigmaWitness {
            s_i: sk_coeffs,
            e_i: e_coeffs,
        };

        // Compute poly_commit identically to Round1Message for Fiat-Shamir binding.
        let mut poly_commit_data = Vec::new();
        poly_commit_data.extend_from_slice(session_id);
        poly_commit_data.extend_from_slice(&party_id.to_be_bytes());
        poly_commit_data.extend_from_slice(&share.bytes.0);
        let poly_commit = hash_bytes(b"poly-commit/v1", &poly_commit_data);

        let proof = sigma::prove(session_id, party_id, &stmt, &wit, &mut rng, &poly_commit)
            .map_err(|e| format!("sigma prove: {e}"))?;

        // Serialize the sigma proof into a compact bundle.
        let mut buf = Vec::with_capacity(8192 * 8 * 3 + 8);
        encode_sigma_proof(&proof, &mut buf);
        Ok(buf)
    }

    fn _prove_share_nizk(
        &self,
        session_id: &[u8; 32],
        dealer_id: PartyId,
        recipient_id: PartyId,
        ct: &Ciphertext,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, pvthfhe_nizk::NizkError> {
        let session_str = hex::encode(session_id);
        let participant_id =
            u16::try_from(dealer_id).map_err(|_| pvthfhe_nizk::NizkError::InvalidInput {
                reason: "dealer_id too large",
                party_id: None,
            })?;

        let pvss_commitment = {
            let mut h = Sha256::new();
            h.update(session_id);
            h.update(&dealer_id.to_be_bytes());
            h.update(plaintext);
            let mut out = [0u8; 32];
            out.copy_from_slice(&h.finalize());
            out
        };

        let statement = NizkStatement {
            ciphertext_bytes: ct.bytes.clone(),
            decrypt_share_bytes: vec![0u8; 32],
            pvss_commitment,
            params: (
                65_537,
                pvthfhe_nizk::sigma::rlwe_n(),
                pvthfhe_nizk::sigma::SIGMA_B_E as u64,
            ),
            session_id: session_str,
            participant_id,
            epoch: 0,
        };

        let secret_share = if plaintext.len() >= 8 {
            u64::from_le_bytes(plaintext[..8].try_into().unwrap_or([0u8; 8]))
        } else {
            let mut buf = [0u8; 8];
            let len = plaintext.len().min(8);
            buf[..len].copy_from_slice(&plaintext[..len]);
            u64::from_le_bytes(buf)
        };

        let secret_share_poly = derive_witness_poly(plaintext);
        let error = derive_nizk_error_poly(plaintext);

        let mut rng_seed = [0u8; 32];
        {
            let mut h = Sha256::new();
            h.update(Tag::SimNizkRng.as_bytes());
            h.update(session_id);
            h.update(&dealer_id.to_be_bytes());
            h.update(&recipient_id.to_be_bytes());
            rng_seed.copy_from_slice(&h.finalize());
        }

        let witness = NizkWitness {
            secret_share,
            secret_share_poly,
            error,
            randomness: rng_seed.to_vec(),
        };

        let adapter = CycloNizkAdapter;
        let mut prove_rng = ChaCha8Rng::from_seed(rng_seed); // allow-seeded-rng: deterministic simulator
        let proof = adapter.prove(&statement, &witness, &mut prove_rng)?;

        Ok(proof.proof_bytes)
    }
}

fn derive_witness_poly(bytes: &[u8]) -> Vec<i64> {
    let mut hasher = Sha256::new();
    hasher.update(Tag::SimWitnessPoly.as_bytes());
    hasher.update(bytes);
    let seed: [u8; 32] = hasher.finalize().into();
    let mut rng = ChaCha8Rng::from_seed(seed); // allow-seeded-rng: deterministic simulator
    let n = pvthfhe_nizk::sigma::rlwe_n();
    let range = 3u64;
    let max_multiple = (u64::MAX / range) * range;
    let mut poly = Vec::with_capacity(n);
    while poly.len() < n {
        let v = rng.next_u64();
        if v < max_multiple {
            poly.push((v % range) as i64 - 1);
        }
    }
    poly
}

fn derive_nizk_error_poly(bytes: &[u8]) -> Vec<i64> {
    let mut hasher = Sha256::new();
    hasher.update(Tag::SimNizkError.as_bytes());
    hasher.update(bytes);
    let seed: [u8; 32] = hasher.finalize().into();
    let mut rng = ChaCha8Rng::from_seed(seed); // allow-seeded-rng: deterministic simulator
    let n = pvthfhe_nizk::sigma::rlwe_n();
    let b = pvthfhe_nizk::sigma::SIGMA_B_E as u64;
    let range = 2 * b + 1;
    let max_multiple = (u64::MAX / range) * range;
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let r = rng.next_u64();
        if r < max_multiple {
            out.push((r % range) as i64 - b as i64);
        }
    }
    out
}

fn encode_sigma_proof(proof: &sigma::SigmaProof, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&(proof.z_s.len() as u32).to_le_bytes());
    for &coeff in &proof.z_s {
        buf.extend_from_slice(&coeff.to_le_bytes());
    }
    buf.extend_from_slice(&(proof.z_e.len() as u32).to_le_bytes());
    for &coeff in &proof.z_e {
        buf.extend_from_slice(&coeff.to_le_bytes());
    }
    buf.extend_from_slice(&(proof.t_rns.len() as u32).to_le_bytes());
    for &limb in &proof.t_rns {
        buf.extend_from_slice(&limb.to_le_bytes());
    }
    buf.extend_from_slice(&proof.ch.to_le_bytes());
}
