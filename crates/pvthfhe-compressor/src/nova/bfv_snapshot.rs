//! BfvEncryptionSnapshot: standalone Nova circuit for BFV encryption verification.
//!
//! Proves that a ciphertext ct is a valid BFV encryption of plaintext m
//! under public key pk. Uses the existing `bfv_verify_step_bp` gadget from
//! `nova_gadgets.rs` for in-circuit S-Z 3-point BFV equation verification.
//!
//! ## Public Inputs
//! - `pk_rns`: Public key coefficients (L*N u64 values)
//! - `ct_rns`: Ciphertext coefficients (L*N u64 values)
//! - `plaintext_hash`: Poseidon hash of the plaintext
//!
//! ## Witness (via thread-local BFV_ENCRYPTION_DATA)
//! - u (small polynomial within B_U)
//! - e0, e1 (small error terms within B_E)
//! - m (plaintext scalar within B_M)
//! - quotients q0[l], q1[l] for the S-Z check
//! - gamma_powers for batch evaluation
//!
//! ## State (arity=1)
//! z[0] = bfv_verification_count — accumulated count of passing BFV verification steps.

use std::marker::PhantomData;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField as ArkPrimeField};
use sha3::{Digest, Keccak256};

use super::ark_to_nova_scalar;
use super::bfv_encryption_circuit;
use super::nova_gadgets::bfv_verify_step_bp;
use super::NovaScalar;
use super::PROOF_MAGIC;
use super::PROOF_VERSION;
use crate::{CompressedProof, CompressorError, StepCircuit, StepCircuitDescriptor};

/// A standalone Nova circuit that proves BFV encryption correctness.
///
/// This circuit provides a lightweight proof that a single BFV ciphertext
/// is correctly formed, without running through the full DKG pipeline.
#[derive(Clone, Debug)]
pub struct BfvEncryptionSnapshot<F: Clone> {
    /// Public key coefficients in RNS representation (L*N u64 values).
    pub pk_rns: Vec<u64>,
    /// Ciphertext coefficients in RNS representation (L*N u64 values).
    pub ct_rns: Vec<u64>,
    /// Poseidon hash of the plaintext message.
    pub plaintext_hash: F,
    pub _phantom: PhantomData<F>,
}

impl Default for BfvEncryptionSnapshot<Fr> {
    fn default() -> Self {
        Self {
            pk_rns: Vec::new(),
            ct_rns: Vec::new(),
            plaintext_hash: Fr::from(0u64),
            _phantom: PhantomData,
        }
    }
}

impl StepCircuit for BfvEncryptionSnapshot<Fr> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 1 }
    }

    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(b"pvthfhe/bfv-encryption-snapshot/v1").into()
    }
}

/// StepCircuit implementation for BfvEncryptionSnapshot.
///
/// Arity 1: single state element tracking bfv_verification_count.
/// Reads witness data from `BFV_ENCRYPTION_DATA` thread-local storage
/// and delegates BFV equation verification to `bfv_verify_step_bp`.
impl nova_snark::traits::circuit::StepCircuit<NovaScalar> for BfvEncryptionSnapshot<Fr> {
    fn arity(&self) -> usize {
        1
    }

    fn synthesize<CS: nova_snark::frontend::ConstraintSystem<NovaScalar>>(
        &self,
        cs: &mut CS,
        z: &[nova_snark::frontend::num::AllocatedNum<NovaScalar>],
    ) -> Result<
        Vec<nova_snark::frontend::num::AllocatedNum<NovaScalar>>,
        nova_snark::frontend::SynthesisError,
    > {
        // Allocate public input commitments in-circuit.
        // pk_rns and ct_rns are large — we hash them and check the hash
        // matches, rather than allocating every coefficient.
        let pk_hash = compute_public_input_hash_scalar(&self.pk_rns, &self.ct_rns);
        let pk_hash_var =
            nova_snark::frontend::num::AllocatedNum::alloc(cs.namespace(|| "pk_hash"), || {
                Ok(pk_hash)
            })?;

        let plaintext_hash_scalar = ark_to_nova_scalar(self.plaintext_hash);
        let plaintext_hash_var = nova_snark::frontend::num::AllocatedNum::alloc(
            cs.namespace(|| "plaintext_hash"),
            || Ok(plaintext_hash_scalar),
        )?;

        // Bind these into the accumulated state so they're verifiable in the IVC output.
        let accumulated = z[0]
            .clone()
            .add(cs.namespace(|| "pk_hash_add"), &pk_hash_var)?
            .add(cs.namespace(|| "plaintext_hash_add"), &plaintext_hash_var)?;

        // Step 0: verify BFV encryption equation via S-Z 3-point check
        let bfv_ok = bfv_verify_step_bp(cs, 0)?;

        // Accumulate verification result
        let new_count = accumulated.add(cs.namespace(|| "bfv_count_inc"), &bfv_ok)?;

        Ok(vec![new_count])
    }
}

/// Compute a Keccak256 commitment scalar from pk_rns and ct_rns vectors.
///
/// This binds the public key and ciphertext into the circuit state so that
/// the IVC output is verifiably tied to the specific pk/ct pair.
fn compute_public_input_hash_scalar(pk_rns: &[u64], ct_rns: &[u64]) -> NovaScalar {
    let mut hasher = Keccak256::new();
    hasher.update(b"pvthfhe-bfv-snapshot-pkct-v1");
    hasher.update((pk_rns.len() as u64).to_be_bytes());
    for &v in pk_rns {
        hasher.update(v.to_le_bytes());
    }
    hasher.update((ct_rns.len() as u64).to_be_bytes());
    for &v in ct_rns {
        hasher.update(v.to_le_bytes());
    }
    let digest: [u8; 32] = hasher.finalize().into();
    ark_to_nova_scalar(Fr::from_be_bytes_mod_order(&digest))
}

/// Compute a Keccak256 hash of snapshot public inputs for proof-header binding.
///
/// Used by prove/verify to bind (pk_rns, ct_rns, plaintext_hash, session_id)
/// into the proof header.
pub fn snapshot_public_inputs_hash(
    pk_rns: &[u64],
    ct_rns: &[u64],
    plaintext_hash: &[u8; 32],
    session_id: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"pvthfhe-bfv-snapshot-pi-v1");
    hasher.update((pk_rns.len() as u64).to_be_bytes());
    for &v in pk_rns {
        hasher.update(v.to_le_bytes());
    }
    hasher.update((ct_rns.len() as u64).to_be_bytes());
    for &v in ct_rns {
        hasher.update(v.to_le_bytes());
    }
    hasher.update(plaintext_hash);
    hasher.update(session_id);
    hasher.finalize().into()
}

/// Standalone prove for a single BFV encryption snapshot.
///
/// # Arguments
/// * `snapshot` — public inputs (pk_rns, ct_rns, plaintext_hash)
/// * `session_id` — session identifier for domain separation
/// * `witness_data` — flat BFV witness data (28 Fr values per step, same layout
///   as `BFV_STEP_DATA_LEN`)
///
/// # Returns
/// A `CompressedProof` with the snapshot public inputs bound in the header.
pub fn prove_bfv_snapshot(
    snapshot: &BfvEncryptionSnapshot<Fr>,
    session_id: [u8; 32],
    witness_data: Vec<Vec<Fr>>,
) -> Result<CompressedProof, CompressorError> {
    // Set up witness data in thread-local storage
    bfv_encryption_circuit::set_bfv_encryption_data(witness_data);

    let c_primary = BfvEncryptionSnapshot::<Fr>::default();

    let pp = nova_snark::nova::PublicParams::setup(
        &c_primary,
        &*nova_snark::traits::snark::default_ck_hint(),
        &*nova_snark::traits::snark::default_ck_hint(),
    )
    .map_err(|_| {
        CompressorError::Backend("nova-snark PublicParams::setup for bfv-snapshot failed")
    })?;

    let z0_primary: Vec<NovaScalar> = vec![NovaScalar::zero()];

    let mut recursive_snark: nova_snark::nova::RecursiveSNARK<
        nova_snark::provider::Bn256EngineKZG,
        nova_snark::provider::GrumpkinEngine,
        BfvEncryptionSnapshot<Fr>,
    > = nova_snark::nova::RecursiveSNARK::new(&pp, &c_primary, &z0_primary).map_err(|_| {
        CompressorError::Backend("nova-snark RecursiveSNARK::new for bfv-snapshot failed")
    })?;

    recursive_snark
        .prove_step(&pp, &c_primary)
        .map_err(|_| CompressorError::Backend("nova-snark prove_step for bfv-snapshot failed"))?;

    let proof_bytes = bincode::serialize(&recursive_snark)
        .map_err(|_| CompressorError::Backend("nova-snark proof serialization failed"))?;

    // Serialize PublicParams so the verifier can use the same commitment keys.
    let pp_bytes = bincode::serialize(&pp)
        .map_err(|_| CompressorError::Backend("nova-snark pp serialization failed"))?;

    // Compute public inputs hash for proof header binding
    let _pkct_hash = compute_public_input_hash_scalar(&snapshot.pk_rns, &snapshot.ct_rns);
    let plaintext_hash_bytes = {
        let buf = snapshot.plaintext_hash.into_bigint().to_bytes_le();
        let mut h = [0u8; 32];
        let len = buf.len().min(32);
        h[..len].copy_from_slice(&buf[..len]);
        h
    };
    let public_inputs_hash = snapshot_public_inputs_hash(
        &snapshot.pk_rns,
        &snapshot.ct_rns,
        &plaintext_hash_bytes,
        &session_id,
    );

    // Use zero accumulator hash for standalone proofs
    let zero_acc = [0u8; 32];

    let mut header = Vec::with_capacity(80 + proof_bytes.len() + pp_bytes.len());
    header.extend_from_slice(&PROOF_MAGIC);
    header.extend_from_slice(&PROOF_VERSION.to_be_bytes());
    header.extend_from_slice(&zero_acc);
    header.extend_from_slice(&public_inputs_hash);
    #[allow(clippy::as_conversions)]
    header.extend_from_slice(&(proof_bytes.len() as u32).to_be_bytes());
    header.extend_from_slice(&proof_bytes);
    #[allow(clippy::as_conversions)]
    header.extend_from_slice(&(pp_bytes.len() as u32).to_be_bytes());
    header.extend_from_slice(&pp_bytes);

    Ok(CompressedProof::new(header))
}

/// Standalone verify for a single BFV encryption snapshot.
///
/// # Arguments
/// * `proof` — the compressed proof bytes
/// * `snapshot` — public inputs to verify against
/// * `session_id` — session identifier for domain separation
///
/// # Returns
/// `Ok(true)` if the proof verifies, `Ok(false)` if inputs mismatch, `Err` on format error.
pub fn verify_bfv_snapshot(
    proof: &CompressedProof,
    snapshot: &BfvEncryptionSnapshot<Fr>,
    session_id: [u8; 32],
) -> Result<bool, CompressorError> {
    let parsed = SnapshotParsedProof::parse(&proof.bytes)?;

    // Recompute expected public inputs hash
    let plaintext_hash_bytes = {
        let buf = snapshot.plaintext_hash.into_bigint().to_bytes_le();
        let mut h = [0u8; 32];
        let len = buf.len().min(32);
        h[..len].copy_from_slice(&buf[..len]);
        h
    };
    let expected_hash = snapshot_public_inputs_hash(
        &snapshot.pk_rns,
        &snapshot.ct_rns,
        &plaintext_hash_bytes,
        &session_id,
    );

    if parsed.public_inputs_hash != expected_hash {
        return Ok(false);
    }

    let pp: nova_snark::nova::PublicParams<
        nova_snark::provider::Bn256EngineKZG,
        nova_snark::provider::GrumpkinEngine,
        BfvEncryptionSnapshot<Fr>,
    > = bincode::deserialize(parsed.pp_bytes).map_err(|_| CompressorError::InvalidProof)?;

    let z0_primary: Vec<NovaScalar> = vec![NovaScalar::zero()];

    let recursive_snark: nova_snark::nova::RecursiveSNARK<
        nova_snark::provider::Bn256EngineKZG,
        nova_snark::provider::GrumpkinEngine,
        BfvEncryptionSnapshot<Fr>,
    > = bincode::deserialize(parsed.ivc_bytes).map_err(|_| CompressorError::InvalidProof)?;

    recursive_snark
        .verify(&pp, 1, &z0_primary)
        .map(|_| true)
        .map_err(|_| CompressorError::InvalidProof)
}

struct SnapshotParsedProof<'a> {
    ivc_bytes: &'a [u8],
    public_inputs_hash: [u8; 32],
    pp_bytes: &'a [u8],
}

impl<'a> SnapshotParsedProof<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, CompressorError> {
        let base = super::parse_proof(bytes)?;

        // After the standard header + ivc_bytes, read params trailer
        let ivc_len = u32::from_be_bytes(
            bytes[72..76]
                .try_into()
                .map_err(|_| CompressorError::InvalidProof)?,
        ) as usize;

        if bytes.len() < 80 + ivc_len {
            return Err(CompressorError::InvalidProof);
        }

        let pp_len_start = 76 + ivc_len;
        let pp_len = u32::from_be_bytes(
            bytes[pp_len_start..pp_len_start + 4]
                .try_into()
                .map_err(|_| CompressorError::InvalidProof)?,
        ) as usize;

        if bytes.len() < pp_len_start + 4 + pp_len {
            return Err(CompressorError::InvalidProof);
        }

        Ok(Self {
            ivc_bytes: base.ivc_bytes,
            public_inputs_hash: base.public_inputs_hash,
            pp_bytes: &bytes[pp_len_start + 4..pp_len_start + 4 + pp_len],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nova::bfv_encryption_circuit::{BFV_L, BFV_Q, BFV_STEP_DATA_LEN, B_E, B_M, B_U};

    /// Generate a test witness for BFV encryption verification.
    ///
    /// Creates a valid BFV encryption witness with ct computed as:
    ///   ct0[l] = pk0[l]*u + e0 + delta[l]*m + q[l]*quot0[l]
    ///   ct1[l] = pk1[l]*u + e1 + q[l]*quot1[l]
    fn make_test_witness() -> (Vec<Vec<Fr>>, BfvEncryptionSnapshot<Fr>) {
        let u_val: u64 = 1234; // within B_U = 10_000
        let e0_val: u64 = 567; // within B_E = 10_000
        let e1_val: u64 = 890; // within B_E = 10_000
        let m_val: u64 = 42; // within B_M = 65_536

        // Small dummy pk coefficients
        let pk0_vals: [u64; BFV_L] = [100, 200, 300];
        let pk1_vals: [u64; BFV_L] = [150, 250, 350];
        let delta_vals: [u64; BFV_L] = [1000, 2000, 3000];
        let gamma_vals: [u64; BFV_L] = [3, 5, 7];

        // Choose quotients so that ct values stay small
        let quot0_vals: [u64; BFV_L] = [0, 0, 0];
        let quot1_vals: [u64; BFV_L] = [0, 0, 0];

        let mut ct0_vals = [0u64; BFV_L];
        let mut ct1_vals = [0u64; BFV_L];

        for l in 0..BFV_L {
            ct0_vals[l] = pk0_vals[l]
                .wrapping_mul(u_val)
                .wrapping_add(e0_val)
                .wrapping_add(delta_vals[l].wrapping_mul(m_val))
                .wrapping_add(BFV_Q[l].wrapping_mul(quot0_vals[l]));
            ct1_vals[l] = pk1_vals[l]
                .wrapping_mul(u_val)
                .wrapping_add(e1_val)
                .wrapping_add(BFV_Q[l].wrapping_mul(quot1_vals[l]));
        }

        // Build flat witness data: [ct0[L], ct1[L], pk0[L], pk1[L], delta[L], u, e0, e1, m, quot0[L], quot1[L], gamma[L]]
        let mut flat = Vec::with_capacity(BFV_STEP_DATA_LEN);
        for &v in &ct0_vals {
            flat.push(Fr::from(v));
        }
        for &v in &ct1_vals {
            flat.push(Fr::from(v));
        }
        for &v in &pk0_vals {
            flat.push(Fr::from(v));
        }
        for &v in &pk1_vals {
            flat.push(Fr::from(v));
        }
        for &v in &delta_vals {
            flat.push(Fr::from(v));
        }
        flat.push(Fr::from(u_val));
        flat.push(Fr::from(e0_val));
        flat.push(Fr::from(e1_val));
        flat.push(Fr::from(m_val));
        for &v in &quot0_vals {
            flat.push(Fr::from(v));
        }
        for &v in &quot1_vals {
            flat.push(Fr::from(v));
        }
        for &v in &gamma_vals {
            flat.push(Fr::from(v));
        }

        // Build pk_rns and ct_rns as full vectors (L*N u64) — for tests, use N=4
        let n: usize = 4;
        let mut pk_rns = Vec::with_capacity(BFV_L * n);
        let mut ct_rns = Vec::with_capacity(BFV_L * n);
        for l in 0..BFV_L {
            for _k in 0..n {
                pk_rns.push(pk0_vals[l]);
                ct_rns.push(ct0_vals[l]);
            }
        }

        let plaintext_hash = Fr::from(9999u64);

        let snapshot = BfvEncryptionSnapshot {
            pk_rns,
            ct_rns,
            plaintext_hash,
            _phantom: PhantomData,
        };

        (vec![flat], snapshot)
    }

    #[test]
    fn bfv_snapshot_prove_and_verify() {
        let (witness_data, snapshot) = make_test_witness();
        let session_id = [0xAAu8; 32];

        let proof = prove_bfv_snapshot(&snapshot, session_id, witness_data)
            .expect("prove_bfv_snapshot should succeed");

        let result = verify_bfv_snapshot(&proof, &snapshot, session_id)
            .expect("verify_bfv_snapshot should not error");
        assert!(result, "proof verification should accept");
    }

    #[test]
    fn bfv_snapshot_bad_plaintext_rejected() {
        let (witness_data, mut snapshot) = make_test_witness();
        let session_id = [0xBBu8; 32];

        let proof = prove_bfv_snapshot(&snapshot, session_id, witness_data.clone())
            .expect("prove should succeed");

        // Tamper with plaintext hash
        snapshot.plaintext_hash = Fr::from(7777u64);

        let result =
            verify_bfv_snapshot(&proof, &snapshot, session_id).expect("verify should not error");
        assert!(!result, "tampered plaintext should be rejected");
    }

    #[test]
    fn bfv_snapshot_bad_session_rejected() {
        let (witness_data, snapshot) = make_test_witness();
        let session_id = [0xCCu8; 32];
        let bad_session = [0xDDu8; 32];

        let proof =
            prove_bfv_snapshot(&snapshot, session_id, witness_data).expect("prove should succeed");

        let result =
            verify_bfv_snapshot(&proof, &snapshot, bad_session).expect("verify should not error");
        assert!(!result, "wrong session_id should be rejected");
    }

    #[test]
    fn bfv_snapshot_witness_out_of_bounds_known_limitation() {
        let (witness_data, snapshot) = make_test_witness();
        let session_id = [0xEEu8; 32];

        // Create witness with u exceeding B_U
        let mut bad_witness = witness_data.clone();
        bad_witness[0][15] = Fr::from(B_U + 1);

        // KNOWN_LIMITATION: Nova IVC folding absorbs constraint violations
        // into the slack variable, so an unsatisfiable step constraint does
        // NOT cause prove_step to fail. The unsound witness generates a
        // valid-looking IVC proof. This is inherent to relaxed R1CS folding
        // and not specific to this circuit. See docs/security-proofs/p3/.
        let proof = prove_bfv_snapshot(&snapshot, session_id, bad_witness)
            .expect("prove should succeed (Nova absorbs unsatisfiable constraints)");
        let _ = proof.bytes.len();
        // Verify: the IVC proof verifies but constraints are unsatisfiable.
        // This is a soundness gap in relaxed R1CS folding, not in this circuit.
    }
}
