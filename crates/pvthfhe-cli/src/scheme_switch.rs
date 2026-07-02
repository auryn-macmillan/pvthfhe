// SPDX-License-Identifier: LGPL-3.0-only
//
// Scheme-Switch: CKKS ↔ TFHE decoder circuit (LatticeFold+ architecture).
// Current implementation: commitment-binding only — the full RLWE/LWE
// decoder circuit is deferred (P5). The commitment layer provides a
// secure transition point for when the circuit is ready.

use pvthfhe_cyclo::{CcsPShareInstance, CycloError};
use pvthfhe_domain_tags::Tag;
use pvthfhe_types::ProtocolBytes;
use sha2::{Digest, Sha256};

/// Scheme-switch statement: what the verifier must check.
#[derive(Debug, Clone)]
pub struct SchemeSwitchStatement {
    pub ckks_ct_hash: [u8; 32],
    pub tfhe_bit_commitment: [u8; 32],
    pub num_bits: usize,
    pub ckks_tolerance: f64,
    pub session_id: [u8; 32],
}

/// Scheme-switch witness: the prover's private data.
#[derive(Debug, Clone)]
pub struct SchemeSwitchWitness {
    /// CKKS-decoded plaintext (f64).
    pub ckks_plaintext: f64,
    /// TFHE plaintext bits.
    pub tfhe_bits: Vec<bool>,
    /// CKKS secret key coefficients (for future RLWE circuit).
    #[allow(dead_code)]
    pub ckks_sk_coeffs: Option<Vec<i64>>,
    /// TFHE secret key (for future LWE circuit).
    #[allow(dead_code)]
    pub tfhe_sk: Option<Vec<i64>>,
}

/// Produces a CCS instance that binds the scheme-switch commitment.
///
/// The commitment encodes: SHA-256(ckks_ct_hash || tfhe_bit_commitment || tolerance || session_id).
/// The witness bytes encode the CKKS plaintext + TFHE bits (for future circuit extraction).
/// The public IO encodes the statement.
pub fn scheme_switch_prove(
    stmt: &SchemeSwitchStatement,
    wit: &SchemeSwitchWitness,
) -> Result<CcsPShareInstance, CycloError> {
    let tfhe_bit_hash = compute_tfhe_bit_commitment(&wit.tfhe_bits);

    let binding = scheme_switch_binding(
        &stmt.ckks_ct_hash,
        &tfhe_bit_hash,
        stmt.ckks_tolerance,
        &stmt.session_id,
    );

    // ── Build witness bytes ──────────────────────────────────────────
    let wit_bytes = encode_scheme_switch_witness(wit)?;
    let public_io = encode_scheme_switch_statement(stmt, &tfhe_bit_hash);

    Ok(CcsPShareInstance {
        participant_id: 0,
        ajtai_commitment_bytes: ProtocolBytes(binding.to_vec()),
        public_io_bytes: ProtocolBytes(public_io),
        ccs_witness_bytes: pvthfhe_types::CcsWitnessSecret::new(wit_bytes),
        sha256_binding_bytes: ProtocolBytes(binding.to_vec()),
        ccs_matrix_bytes: ProtocolBytes(vec![]),
    })
}

/// Verifies the commitment-binding of a scheme-switch instance.
///
/// Does NOT verify the full RLWE/LWE decryption — that requires the LatticeFold+
/// circuit. This check ensures the instance is structurally consistent.
pub fn scheme_switch_verify(
    stmt: &SchemeSwitchStatement,
    instance: &CcsPShareInstance,
) -> Result<(), CycloError> {
    let expected_binding = scheme_switch_binding(
        &stmt.ckks_ct_hash,
        &stmt.tfhe_bit_commitment,
        stmt.ckks_tolerance,
        &stmt.session_id,
    );

    if instance.sha256_binding_bytes.as_slice() != expected_binding.as_slice() {
        return Err(CycloError::InvalidInstance(
            "scheme-switch binding mismatch".into(),
        ));
    }
    Ok(())
}

/// Computes the scheme-switch transcript binding.
///
/// Binds together: CKKS ciphertext identity, TFHE plaintext commitment,
/// tolerance, and session. Domain-separated via `Tag::SchemeSwitch`.
pub fn scheme_switch_binding(
    ckks_ct_hash: &[u8; 32],
    tfhe_commitment: &[u8; 32],
    tolerance: f64,
    session_id: &[u8; 32],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(Tag::SchemeSwitch.as_bytes())
        .chain_update(ckks_ct_hash)
        .chain_update(tfhe_commitment)
        .chain_update(tolerance.to_le_bytes())
        .chain_update(session_id)
        .finalize()
        .into()
}

/// Hashes a bit vector into a 32-byte commitment.
pub fn compute_tfhe_bit_commitment(bits: &[bool]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(Tag::SchemeSwitch.as_bytes());
    h.update(b"tfhe-bits/v1");
    for bit in bits {
        h.update([*bit as u8]);
    }
    h.finalize().into()
}

/// Compute Merkle-style root of TFHE ciphertext hashes.
fn compute_tfhe_ct_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }
    let mut h = Sha256::new();
    for hash in hashes {
        h.update(hash);
    }
    h.finalize().into()
}

/// Encode the witness into CCS-wire-compatible bytes.
fn encode_scheme_switch_witness(wit: &SchemeSwitchWitness) -> Result<Vec<u8>, CycloError> {
    let mut buf = Vec::new();
    // Version tag
    buf.extend_from_slice(b"pvh-ss-wit1");
    // CKKS plaintext as le bytes
    buf.extend_from_slice(&wit.ckks_plaintext.to_le_bytes());
    // Bit count
    buf.extend_from_slice(&(wit.tfhe_bits.len() as u16).to_le_bytes());
    // TFHE bits
    for bit in &wit.tfhe_bits {
        buf.push(*bit as u8);
    }
    Ok(buf)
}

/// Encode the statement into public-IO-compatible bytes.
fn encode_scheme_switch_statement(
    stmt: &SchemeSwitchStatement,
    tfhe_bit_hash: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"pvh-ss-pub1");
    buf.extend_from_slice(&stmt.ckks_ct_hash);
    buf.extend_from_slice(tfhe_bit_hash);
    buf.extend_from_slice(&stmt.ckks_tolerance.to_le_bytes());
    buf.extend_from_slice(&(stmt.num_bits as u16).to_le_bytes());
    buf.extend_from_slice(&stmt.session_id);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_switch_binding_deterministic() {
        let ckks_hash = [1u8; 32];
        let tfhe_commit = [2u8; 32];
        let session = [3u8; 32];
        let b1 = scheme_switch_binding(&ckks_hash, &tfhe_commit, 10.0, &session);
        let b2 = scheme_switch_binding(&ckks_hash, &tfhe_commit, 10.0, &session);
        assert_eq!(b1, b2);
    }

    #[test]
    fn scheme_switch_binding_different_tolerance() {
        let ckks_hash = [1u8; 32];
        let tfhe_commit = [2u8; 32];
        let session = [3u8; 32];
        let b1 = scheme_switch_binding(&ckks_hash, &tfhe_commit, 10.0, &session);
        let b2 = scheme_switch_binding(&ckks_hash, &tfhe_commit, 1.0, &session);
        assert_ne!(b1, b2);
    }

    #[test]
    fn prove_verify_roundtrip() {
        let wit = SchemeSwitchWitness {
            ckks_plaintext: 3528.0,
            tfhe_bits: vec![false, false, false, true, false, true, true, true],
            ckks_sk_coeffs: None,
            tfhe_sk: None,
        };
        let stmt = SchemeSwitchStatement {
            ckks_ct_hash: [0xAA; 32],
            tfhe_bit_commitment: compute_tfhe_bit_commitment(&wit.tfhe_bits),
            num_bits: 8,
            ckks_tolerance: 10.0,
            session_id: [0xCC; 32],
        };

        let instance = scheme_switch_prove(&stmt, &wit).unwrap();
        scheme_switch_verify(&stmt, &instance).unwrap();
    }

    #[test]
    fn scheme_switch_binding_different_session() {
        let ckks_hash = [1u8; 32];
        let tfhe_commit = [2u8; 32];
        let session_a = [3u8; 32];
        let session_b = [4u8; 32];
        let b1 = scheme_switch_binding(&ckks_hash, &tfhe_commit, 10.0, &session_a);
        let b2 = scheme_switch_binding(&ckks_hash, &tfhe_commit, 10.0, &session_b);
        assert_ne!(b1, b2);
    }

    #[test]
    fn scheme_switch_prove_empty_bits() {
        let wit = SchemeSwitchWitness {
            ckks_plaintext: 0.0,
            tfhe_bits: vec![],
            ckks_sk_coeffs: None,
            tfhe_sk: None,
        };
        let stmt = SchemeSwitchStatement {
            ckks_ct_hash: [0xBB; 32],
            tfhe_bit_commitment: compute_tfhe_bit_commitment(&[]),
            num_bits: 0,
            ckks_tolerance: 1.0,
            session_id: [0xDD; 32],
        };
        let instance = scheme_switch_prove(&stmt, &wit).unwrap();
        scheme_switch_verify(&stmt, &instance).unwrap();
    }

    #[test]
    fn scheme_switch_prove_all_zeros_bits() {
        let bits = vec![false; 64];
        let wit = SchemeSwitchWitness {
            ckks_plaintext: 0.0,
            tfhe_bits: bits.clone(),
            ckks_sk_coeffs: None,
            tfhe_sk: None,
        };
        let stmt = SchemeSwitchStatement {
            ckks_ct_hash: [0xEE; 32],
            tfhe_bit_commitment: compute_tfhe_bit_commitment(&bits),
            num_bits: 64,
            ckks_tolerance: 1.0,
            session_id: [0xFF; 32],
        };
        let instance = scheme_switch_prove(&stmt, &wit).unwrap();
        scheme_switch_verify(&stmt, &instance).unwrap();
    }

    #[test]
    fn scheme_switch_verify_rejects_wrong_commitment() {
        let wit = SchemeSwitchWitness {
            ckks_plaintext: 100.0,
            tfhe_bits: vec![true, false, true],
            ckks_sk_coeffs: None,
            tfhe_sk: None,
        };
        let stmt = SchemeSwitchStatement {
            ckks_ct_hash: [0x11; 32],
            tfhe_bit_commitment: compute_tfhe_bit_commitment(&wit.tfhe_bits),
            num_bits: 3,
            ckks_tolerance: 5.0,
            session_id: [0x22; 32],
        };
        let instance = scheme_switch_prove(&stmt, &wit).unwrap();

        // Tamper with the commitment
        let wrong_stmt = SchemeSwitchStatement {
            tfhe_bit_commitment: [0u8; 32],
            ..stmt.clone()
        };
        let result = scheme_switch_verify(&wrong_stmt, &instance);
        assert!(result.is_err(), "verify should reject wrong commitment");
    }
}
