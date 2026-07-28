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

mod codec;
mod cyclo;
mod extract;

pub use codec::append_accumulator_to_proof;
pub use extract::{
    extract_ajtai_commitment_from_proof, extract_ccs_witness_from_proof, extract_sigma_proof,
    extract_sigma_statement_and_proof,
};

use crate::sigma::{self, rlwe_n, SigmaStatement, SigmaWitness};
use crate::{NizkAdapter, NizkError, NizkProof, NizkStatement, NizkWitness, BACKEND_ID};

use codec::{decode_sigma_section_multi, encode_proof_multi, Cursor};
use crate::ajtai::{AJTAI_RANK, PHI};
use cyclo::{
    ajtai_sigma_session_binding, compute_ajtai_commitment, compute_ccs_instance_id,
    derive_epoch_crs_seed, expand_c_rns, serialize_ajtai_commitment, verify_accumulator_transcript,
    verify_ajtai_commitment,
};

use rand_core::RngCore;
use subtle::ConstantTimeEq;

pub(crate) const PROOF_VERSION: u16 = 0x0002;

/// Maximum allowed proof byte length (prevents heap-exhaustion from crafted proof).
const MAX_PROOF_BYTES: usize = 33_554_432; // 32 MiB — G1: N=8192 × 90-round sigma = 17.7 MB, + margin

/// Maximum ciphertext/share byte length.
const MAX_INPUT_BYTES: usize = 1_048_576; // 1 MiB

/// Maximum session_id length in bytes.
const MAX_SESSION_ID_LEN: usize = 256;

/// Maximum number of participants in a batch_verify call.
const MAX_BATCH_STMTS: usize = 1024;

pub(super) fn ajtai_m() -> usize {
    rlwe_n() / crate::ajtai::PHI
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

        let s_i = witness.secret_share_poly.clone();
        let e_i = witness.error.clone();

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
        validate_statement(stmt)?;
        if proof.backend_id != BACKEND_ID {
            return Err(NizkError::VerificationFailed {
                reason: "unexpected proof backend",
                party_id: None,
            });
        }
        if proof.proof_bytes.len() > MAX_PROOF_BYTES {
            return Err(NizkError::InvalidInput {
                reason: "proof too large",
                party_id: None,
            });
        }

        let mut cur = Cursor::new(&proof.proof_bytes);

        let version = cur.read_u16()?;
        if version != PROOF_VERSION {
            return Err(NizkError::InvalidProof {
                reason: "unsupported proof version",
                party_id: Some(stmt.participant_id),
            });
        }

        let ccs_id: [u8; 32] =
            cur.read_exact(32)?
                .try_into()
                .map_err(|_| NizkError::InvalidProof {
                    reason: "bad ccs_instance_id",
                    party_id: Some(stmt.participant_id),
                })?;

        let expected_ccs_id = compute_ccs_instance_id(stmt)?;
        if ccs_id != expected_ccs_id {
            return Err(NizkError::VerificationFailed {
                reason: "ccs_instance_id mismatch",
                party_id: Some(stmt.participant_id),
            });
        }

        let ajtai_commitment_bytes = cur.read_exact(AJTAI_RANK * PHI * 8)?.to_vec();

        // P1.1: Verify algebraic structure of the Ajtai commitment.
        verify_ajtai_commitment(&ajtai_commitment_bytes)?;

        let session_id_encoded = cur.read_len_prefixed_bytes()?;
        let encoded_pid = cur.read_u16()?;
        let encoded_commitment: [u8; 32] =
            cur.read_exact(32)?
                .try_into()
                .map_err(|_| NizkError::InvalidProof {
                    reason: "bad sha256_binding commitment",
                    party_id: Some(stmt.participant_id),
                })?;

        if session_id_encoded != stmt.session_id.as_bytes() {
            return Err(NizkError::VerificationFailed {
                reason: "session_id mismatch",
                party_id: Some(stmt.participant_id),
            });
        }
        if encoded_pid != stmt.participant_id {
            return Err(NizkError::VerificationFailed {
                reason: "participant_id mismatch",
                party_id: Some(stmt.participant_id),
            });
        }

        let sigma_section_len =
            usize::try_from(cur.read_u32()?).map_err(|_| NizkError::InvalidProof {
                reason: "sigma_section_len overflow",
                party_id: Some(stmt.participant_id),
            })?;
        let sigma_section = cur.read_exact(sigma_section_len)?.to_vec();

        let acc_len = usize::try_from(cur.read_u32()?).map_err(|_| NizkError::InvalidProof {
            reason: "acc_len overflow",
            party_id: Some(stmt.participant_id),
        })?;
        if acc_len > 0 {
            let acc_bytes = cur.read_exact(acc_len)?.to_vec();
            verify_accumulator_transcript(stmt, &acc_bytes, &ajtai_commitment_bytes)?;
        }

        cur.finish()?;

        let (d_rns, sigma_multi) = decode_sigma_section_multi(&sigma_section)?;

        if sigma_multi.rounds.is_empty() {
            return Err(NizkError::VerificationFailed {
                reason: "sigma multi-proof must have at least one round",
                party_id: Some(stmt.participant_id),
            });
        }

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
            return Err(NizkError::VerificationFailed {
                reason: "pvss_commitment hash binding mismatch",
                party_id: Some(stmt.participant_id),
            });
        }

        Ok(())
    }

    fn batch_verify(&self, stmts: &[NizkStatement], proofs: &[NizkProof]) -> Result<(), NizkError> {
        if stmts.len() != proofs.len() {
            return Err(NizkError::InvalidInput {
                reason: "statement/proof batch length mismatch",
                party_id: None,
            });
        }
        if stmts.len() > MAX_BATCH_STMTS {
            return Err(NizkError::InvalidInput {
                reason: "batch_verify participant count exceeds maximum",
                party_id: None,
            });
        }
        for (s, p) in stmts.iter().zip(proofs.iter()) {
            self.verify(s, p)?;
        }
        Ok(())
    }
}

pub(super) fn validate_statement(stmt: &NizkStatement) -> Result<(), NizkError> {
    if stmt.params.0 == 0 {
        return Err(NizkError::InvalidInput {
            reason: "q must be non-zero",
            party_id: Some(stmt.participant_id),
        });
    }
    if stmt.params.1 == 0 {
        return Err(NizkError::InvalidInput {
            reason: "ring degree must be non-zero",
            party_id: Some(stmt.participant_id),
        });
    }
    if stmt.params.1 != rlwe_n() {
        return Err(NizkError::InvalidInput {
            reason: "ring degree must match active preset N",
            party_id: Some(stmt.participant_id),
        });
    }
    if stmt.session_id.is_empty() {
        return Err(NizkError::InvalidInput {
            reason: "session_id must be non-empty",
            party_id: Some(stmt.participant_id),
        });
    }
    if stmt.session_id.len() > MAX_SESSION_ID_LEN {
        return Err(NizkError::InvalidInput {
            reason: "session_id too long",
            party_id: Some(stmt.participant_id),
        });
    }
    if stmt.ciphertext_bytes.is_empty() {
        return Err(NizkError::InvalidInput {
            reason: "ciphertext bytes must be non-empty",
            party_id: Some(stmt.participant_id),
        });
    }
    if stmt.ciphertext_bytes.len() > MAX_INPUT_BYTES {
        return Err(NizkError::InvalidInput {
            reason: "ciphertext bytes too large",
            party_id: Some(stmt.participant_id),
        });
    }
    if stmt.decrypt_share_bytes.is_empty() {
        return Err(NizkError::InvalidInput {
            reason: "decrypt-share bytes must be non-empty",
            party_id: Some(stmt.participant_id),
        });
    }
    if stmt.decrypt_share_bytes.len() > MAX_INPUT_BYTES {
        return Err(NizkError::InvalidInput {
            reason: "decrypt-share bytes too large",
            party_id: Some(stmt.participant_id),
        });
    }
    Ok(())
}

fn validate_witness(witness: &NizkWitness) -> Result<(), NizkError> {
    let n = rlwe_n();
    if witness.secret_share_poly.len() != n {
        return Err(NizkError::InvalidInput {
            reason: "secret_share_poly must have exactly N coefficients",
            party_id: None,
        });
    }
    if witness.error.len() != n {
        return Err(NizkError::InvalidInput {
            reason: "error must have exactly N coefficients",
            party_id: None,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma::rlwe_n;
    use crate::NizkAdapter;

    /// Construct a minimal valid Ajtai commitment byte vector.
    /// Returns 26624 bytes: 13 ring elements, each 256 i64 LE coefficients.
    /// The first coefficient is set to 1; all others are 0.
    fn minimal_valid_ajtai_commitment() -> Vec<u8> {
        let mut bytes = vec![0u8; 26_624];
        // Set first coefficient to 1 (i64 LE = [1, 0, 0, 0, 0, 0, 0, 0])
        bytes[0] = 1;
        bytes
    }

    /// Construct minimal proof bytes with `num_rounds` sigma rounds.
    /// d_rns is empty (0 u64s), sigma section has num_rounds with no per-round data.
    fn minimal_proof_bytes(stmt: &NizkStatement, num_rounds: u32) -> Vec<u8> {
        let ccs_id = compute_ccs_instance_id(stmt).expect("ccs_id");
        let ajtai = minimal_valid_ajtai_commitment();
        let sid = stmt.session_id.as_bytes();

        let mut out = Vec::new();
        out.extend_from_slice(&PROOF_VERSION.to_be_bytes());
        out.extend_from_slice(&ccs_id);
        out.extend_from_slice(&ajtai);

        let sid_len = u32::try_from(sid.len()).unwrap();
        out.extend_from_slice(&sid_len.to_be_bytes());
        out.extend_from_slice(sid);
        out.extend_from_slice(&stmt.participant_id.to_be_bytes());
        out.extend_from_slice(&stmt.pvss_commitment);

        // Sigma section: d_rns (count=0) + num_rounds
        let mut sigma_section = Vec::new();
        sigma_section.extend_from_slice(&0u32.to_be_bytes()); // d_rns count = 0
        sigma_section.extend_from_slice(&num_rounds.to_be_bytes());
        let sigma_len = u32::try_from(sigma_section.len()).unwrap();
        out.extend_from_slice(&sigma_len.to_be_bytes());
        out.extend_from_slice(&sigma_section);

        // Empty accumulator
        out.extend_from_slice(&0u32.to_be_bytes());
        out
    }

    /// F1 RED: verify must reject NIZK proofs with zero sigma rounds.
    /// A zero-round sigma proof passes vacuously without the empty-rounds guard.
    #[test]
    fn test_verify_rejects_zero_round_nizk() {
        let stmt = NizkStatement {
            ciphertext_bytes: vec![0u8; 32],
            decrypt_share_bytes: vec![0u8; 32],
            pvss_commitment: [0xAAu8; 32],
            params: (65_537, rlwe_n(), 16),
            session_id: "test-f1".to_owned(),
            participant_id: 1,
            epoch: 0,
        };

        let proof_bytes = minimal_proof_bytes(&stmt, 0);
        let proof = NizkProof {
            backend_id: crate::BACKEND_ID.to_owned(),
            proof_bytes,
        };

        let adapter = CycloNizkAdapter;
        let result = adapter.verify(&stmt, &proof);
        assert!(
            result.is_err(),
            "F1: CycloNizkAdapter::verify must reject proof with zero sigma rounds. Got: {result:?}"
        );
    }
}
