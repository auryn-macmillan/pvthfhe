//! Versioned accumulator transcript codec for Cyclo LatticeFold+.
//!
//! Wire format (version 0x0001):
//! ```text
//! accumulator_version    : u16 BE = 0x0001
//! params_digest          : 32 bytes (SHA-256 of CycloParams label)
//! fold_depth             : u32 BE
//! acc_commitment_bytes   : u32 BE len + data
//! acc_public_io_bytes    : u32 BE len + data
//! norm_bound_current     : u64 BE
//! session_id             : u32 BE len + UTF-8 data
//! instance_count         : u32 BE
//! --per-instance section (repeated instance_count times):
//!   participant_id        : u16 BE
//!   ajtai_commitment_hash : 32 bytes (SHA-256 of Ajtai commitment)
//!   public_io_binding     : 32 bytes (SHA-256 of public I/O)
//!   sha256_binding        : 32 bytes
//! ```

use crate::fiat_shamir;
use crate::fold::AJTAI_COMMITMENT_BYTES;
use crate::{CcsPShareInstance, CycloAccumulator, CycloError, PVTHFHE_CYCLO_PARAMS};
use sha2::{Digest, Sha256};

/// Current accumulator wire format version.
pub const ACCUMULATOR_VERSION: u16 = 0x0001;

/// Reference to a folded instance carried in the accumulator transcript.
///
/// Contains cryptographic hashes that bind the instance to the statement
/// without including the full Ajtai commitment (26,624 bytes per instance).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccumulatorInstanceRef {
    /// Participant identifier (1-based).
    pub participant_id: u16,
    /// SHA-256 of the Ajtai commitment bytes.
    pub ajtai_commitment_hash: [u8; 32],
    /// SHA-256 of the public I/O bytes.
    pub public_io_binding: [u8; 32],
    /// SHA-256 binding tag from the CcsPShareInstance.
    pub sha256_binding: [u8; 32],
}

/// Compute the expected params digest for the locked parameter set.
pub fn params_digest() -> [u8; 32] {
    fiat_shamir::params_digest_v1(b"pvthfhe-cyclo-params-v1")
}

/// Encode an accumulator and instance list into the versioned wire format.
///
/// Returns the serialized bytes ready for inclusion in a NIZK proof trailer.
pub fn encode_accumulator(
    acc: &CycloAccumulator,
    instances: &[CcsPShareInstance],
) -> Result<Vec<u8>, CycloError> {
    let count = u32::try_from(instances.len())
        .map_err(|_| CycloError::InvalidInstance("instance count overflows u32"))?;

    if acc.fold_depth != count {
        return Err(CycloError::InvalidInstance(
            "fold_depth must equal instance count",
        ));
    }

    // Validate instance bindings are exactly 32 bytes.
    for (i, inst) in instances.iter().enumerate() {
        if inst.sha256_binding_bytes.as_slice().len() != 32 {
            return Err(CycloError::InvalidInstance(
                "sha256_binding_bytes must be exactly 32 bytes",
            ));
        }
        if inst.ajtai_commitment_bytes.as_slice().len() != AJTAI_COMMITMENT_BYTES {
            return Err(CycloError::InvalidInstance(
                "ajtai_commitment_bytes must be exactly AJTAI_COMMITMENT_BYTES",
            ));
        }
        // Validate instance_count equals number of instances (for multi-track compat),
        // but don't fail on empty public_io_bytes — they will be checked by verify_fold.
        let _ = i;
    }

    let mut out = Vec::new();

    // accumulator_version: u16 BE
    out.extend_from_slice(&ACCUMULATOR_VERSION.to_be_bytes());

    // params_digest: 32 bytes
    out.extend_from_slice(&acc.params_digest);

    // fold_depth: u32 BE
    out.extend_from_slice(&acc.fold_depth.to_be_bytes());

    // acc_commitment_bytes: u32 BE len + data
    let commit_len = u32::try_from(acc.acc_commitment_bytes.len())
        .map_err(|_| CycloError::InvalidInstance("commitment length overflows u32"))?;
    out.extend_from_slice(&commit_len.to_be_bytes());
    out.extend_from_slice(&acc.acc_commitment_bytes);

    // acc_public_io_bytes: u32 BE len + data
    let io_len = u32::try_from(acc.acc_public_io_bytes.len())
        .map_err(|_| CycloError::InvalidInstance("public_io length overflows u32"))?;
    out.extend_from_slice(&io_len.to_be_bytes());
    out.extend_from_slice(&acc.acc_public_io_bytes);

    // norm_bound_current: u64 BE
    out.extend_from_slice(&acc.norm_bound_current.to_be_bytes());

    // session_id: u32 BE len + UTF-8 data
    let sid_bytes = acc.session_id.as_bytes();
    let sid_len = u32::try_from(sid_bytes.len())
        .map_err(|_| CycloError::InvalidInstance("session_id length overflows u32"))?;
    out.extend_from_slice(&sid_len.to_be_bytes());
    out.extend_from_slice(sid_bytes);

    // instance_count: u32 BE
    out.extend_from_slice(&count.to_be_bytes());

    // Per-instance section
    for inst in instances {
        // participant_id: u16 BE
        out.extend_from_slice(&inst.participant_id.to_be_bytes());

        // ajtai_commitment_hash: SHA-256 of commitment bytes
        let a_hash: [u8; 32] = Sha256::new()
            .chain_update(inst.ajtai_commitment_bytes.as_slice())
            .finalize()
            .into();
        out.extend_from_slice(&a_hash);

        // public_io_binding: SHA-256 of public I/O bytes
        let p_hash: [u8; 32] = Sha256::new()
            .chain_update(inst.public_io_bytes.as_slice())
            .finalize()
            .into();
        out.extend_from_slice(&p_hash);

        // sha256_binding: 32 bytes direct from instance
        let binding = inst.sha256_binding_bytes.as_slice();
        out.extend_from_slice(binding);
    }

    Ok(out)
}

/// Decode a versioned accumulator transcript from bytes.
///
/// Returns the reconstructed [`CycloAccumulator`] and the per-instance
/// hash references. The caller must supply the actual [`CcsPShareInstance`]
/// objects to complete fold verification via [`super::fold::verify_fold`].
///
/// # Errors
///
/// Returns [`CycloError`] for:
/// - Unknown or unsupported version
/// - Truncated data at any field boundary
/// - Invalid lengths (commitment ≠ 26,624 bytes, public IO ≠ 32 bytes)
/// - `params_digest` mismatch
/// - `norm_bound_current` exceeding `beta_at_t`
/// - Duplicate participant IDs in the instance list
pub fn decode_accumulator(
    bytes: &[u8],
) -> Result<(CycloAccumulator, Vec<AccumulatorInstanceRef>), CycloError> {
    let mut pos = 0usize;

    // accumulator_version: u16 BE
    if bytes.len() < pos + 2 {
        return Err(CycloError::InvalidInstance(
            "accumulator transcript: truncated at version",
        ));
    }
    let version = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
    pos += 2;
    if version != ACCUMULATOR_VERSION {
        return Err(CycloError::InvalidInstance(
            "accumulator transcript: unsupported version",
        ));
    }

    // params_digest: 32 bytes
    if bytes.len() < pos + 32 {
        return Err(CycloError::InvalidInstance(
            "accumulator transcript: truncated at params_digest",
        ));
    }
    let mut decoded_digest = [0u8; 32];
    decoded_digest.copy_from_slice(&bytes[pos..pos + 32]);
    pos += 32;
    let expected_digest = params_digest();
    if decoded_digest != expected_digest {
        return Err(CycloError::InvalidInstance(
            "accumulator transcript: params_digest mismatch",
        ));
    }

    // fold_depth: u32 BE
    if bytes.len() < pos + 4 {
        return Err(CycloError::InvalidInstance(
            "accumulator transcript: truncated at fold_depth",
        ));
    }
    let fold_depth =
        u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
    pos += 4;

    // acc_commitment_bytes: u32 BE len + data
    if bytes.len() < pos + 4 {
        return Err(CycloError::InvalidInstance(
            "accumulator transcript: truncated at commitment length",
        ));
    }
    let commit_len =
        u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]) as usize;
    pos += 4;
    if commit_len != AJTAI_COMMITMENT_BYTES {
        return Err(CycloError::InvalidInstance(
            "accumulator transcript: acc_commitment_bytes must be 26624 bytes",
        ));
    }
    if bytes.len() < pos + commit_len {
        return Err(CycloError::InvalidInstance(
            "accumulator transcript: truncated at commitment data",
        ));
    }
    let acc_commitment_bytes = bytes[pos..pos + commit_len].to_vec();
    pos += commit_len;

    // acc_public_io_bytes: u32 BE len + data
    if bytes.len() < pos + 4 {
        return Err(CycloError::InvalidInstance(
            "accumulator transcript: truncated at public_io length",
        ));
    }
    let io_len =
        u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]) as usize;
    pos += 4;
    if io_len != 32 {
        return Err(CycloError::InvalidInstance(
            "accumulator transcript: acc_public_io_bytes must be 32 bytes",
        ));
    }
    if bytes.len() < pos + io_len {
        return Err(CycloError::InvalidInstance(
            "accumulator transcript: truncated at public_io data",
        ));
    }
    let acc_public_io_bytes = bytes[pos..pos + io_len].to_vec();
    pos += io_len;

    // norm_bound_current: u64 BE
    if bytes.len() < pos + 8 {
        return Err(CycloError::InvalidInstance(
            "accumulator transcript: truncated at norm_bound_current",
        ));
    }
    let norm_bound_current = u64::from_be_bytes([
        bytes[pos],
        bytes[pos + 1],
        bytes[pos + 2],
        bytes[pos + 3],
        bytes[pos + 4],
        bytes[pos + 5],
        bytes[pos + 6],
        bytes[pos + 7],
    ]);
    pos += 8;
    if norm_bound_current > PVTHFHE_CYCLO_PARAMS.beta_at_t {
        return Err(CycloError::NormBoundExceeded {
            got: norm_bound_current,
            max: PVTHFHE_CYCLO_PARAMS.beta_at_t,
        });
    }

    // session_id: u32 BE len + UTF-8 data
    if bytes.len() < pos + 4 {
        return Err(CycloError::InvalidInstance(
            "accumulator transcript: truncated at session_id length",
        ));
    }
    let sid_len =
        u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]) as usize;
    pos += 4;
    if bytes.len() < pos + sid_len {
        return Err(CycloError::InvalidInstance(
            "accumulator transcript: truncated at session_id data",
        ));
    }
    let session_id = String::from_utf8(bytes[pos..pos + sid_len].to_vec()).map_err(|_| {
        CycloError::InvalidInstance("accumulator transcript: session_id is not valid UTF-8")
    })?;
    pos += sid_len;

    // instance_count: u32 BE
    if bytes.len() < pos + 4 {
        return Err(CycloError::InvalidInstance(
            "accumulator transcript: truncated at instance_count",
        ));
    }
    let instance_count =
        u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]) as usize;
    pos += 4;

    // Per-instance section: 98 bytes each (2 + 32 + 32 + 32)
    const PER_INSTANCE_BYTES: usize = 2 + 32 + 32 + 32;
    if bytes.len() < pos + instance_count * PER_INSTANCE_BYTES {
        return Err(CycloError::InvalidInstance(
            "accumulator transcript: truncated in per-instance section",
        ));
    }

    let mut instances = Vec::with_capacity(instance_count);
    let mut seen_pids = std::collections::BTreeSet::new();

    for _ in 0..instance_count {
        let participant_id = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        pos += 2;

        let mut ajtai_commitment_hash = [0u8; 32];
        ajtai_commitment_hash.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;

        let mut public_io_binding = [0u8; 32];
        public_io_binding.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;

        let mut sha256_binding = [0u8; 32];
        sha256_binding.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;

        // Reject duplicate participant IDs
        if !seen_pids.insert(participant_id) {
            return Err(CycloError::InvalidInstance(
                "accumulator transcript: duplicate participant_id",
            ));
        }

        instances.push(AccumulatorInstanceRef {
            participant_id,
            ajtai_commitment_hash,
            public_io_binding,
            sha256_binding,
        });
    }

    if fold_depth as usize != instance_count {
        return Err(CycloError::InvalidInstance(
            "accumulator transcript: fold_depth does not match instance_count",
        ));
    }

    if pos != bytes.len() {
        return Err(CycloError::InvalidInstance(
            "accumulator transcript: trailing bytes after instances",
        ));
    }

    let acc = CycloAccumulator {
        fold_depth,
        acc_commitment_bytes,
        acc_public_io_bytes,
        norm_bound_current,
        session_id,
        params_digest: decoded_digest,
    };

    Ok((acc, instances))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use pvthfhe_types::{CcsWitnessSecret, ProtocolBytes};

    fn make_test_instance(pid: u16, _session_id: &str) -> CcsPShareInstance {
        let ajtai_bytes = vec![0u8; AJTAI_COMMITMENT_BYTES];
        let public_io = vec![0u8; 32];
        // Witness: single Fr element = 1
        let mut witness_bytes = Vec::new();
        witness_bytes.extend_from_slice(&1u32.to_be_bytes()); // num_vars = 1
        witness_bytes.extend_from_slice(&[0u8; 32]); // Fr(0) = zero
                                                     // CCS matrix: 1×1, Fr(0)
        let mut matrix_bytes = Vec::new();
        matrix_bytes.extend_from_slice(&1u32.to_be_bytes()); // rows
        matrix_bytes.extend_from_slice(&1u32.to_be_bytes()); // cols
        matrix_bytes.extend_from_slice(&[0u8; 32]); // Fr(0)

        // sha256_binding: 32 deterministic bytes
        let mut sha_binding = [0u8; 32];
        sha_binding[0..2].copy_from_slice(&pid.to_be_bytes());

        CcsPShareInstance {
            participant_id: pid,
            ajtai_commitment_bytes: ProtocolBytes(ajtai_bytes),
            public_io_bytes: ProtocolBytes(public_io),
            ccs_witness_bytes: CcsWitnessSecret::new(witness_bytes),
            sha256_binding_bytes: ProtocolBytes(sha_binding.to_vec()),
            ccs_matrix_bytes: ProtocolBytes(matrix_bytes),
        }
    }

    fn make_test_accumulator(depth: u32, session_id: &str) -> CycloAccumulator {
        CycloAccumulator {
            fold_depth: depth,
            acc_commitment_bytes: vec![0x42u8; AJTAI_COMMITMENT_BYTES],
            acc_public_io_bytes: vec![0u8; 32],
            norm_bound_current: PVTHFHE_CYCLO_PARAMS.beta_at_t,
            session_id: session_id.to_string(),
            params_digest: params_digest(),
        }
    }

    // ── RED tests (write first, before implementation validates them) ──────

    #[test]
    fn test_encode_decode_roundtrip() {
        let session = "roundtrip-test";
        let instances: Vec<_> = (1..=3)
            .map(|pid| make_test_instance(pid, session))
            .collect();
        let acc = make_test_accumulator(3, session);

        let encoded = encode_accumulator(&acc, &instances).expect("encode should succeed");
        let (decoded_acc, decoded_refs) =
            decode_accumulator(&encoded).expect("decode should succeed");

        assert_eq!(decoded_acc.fold_depth, acc.fold_depth);
        assert_eq!(decoded_acc.acc_commitment_bytes, acc.acc_commitment_bytes);
        assert_eq!(decoded_acc.acc_public_io_bytes, acc.acc_public_io_bytes);
        assert_eq!(decoded_acc.norm_bound_current, acc.norm_bound_current);
        assert_eq!(decoded_acc.session_id, acc.session_id);
        assert_eq!(decoded_acc.params_digest, acc.params_digest);
        assert_eq!(decoded_refs.len(), 3);
        assert_eq!(decoded_refs[0].participant_id, 1);
        assert_eq!(decoded_refs[1].participant_id, 2);
        assert_eq!(decoded_refs[2].participant_id, 3);
    }

    #[test]
    fn test_decode_rejects_unknown_version() {
        // Version != 0x0001
        let mut bytes = vec![0x00, 0x02]; // version 0x0002
        bytes.extend_from_slice(&params_digest());
        bytes.extend_from_slice(&0u32.to_be_bytes()); // fold_depth
                                                      // rest is truncated intentionally — version check should come first
        let result = decode_accumulator(&bytes);
        assert!(result.is_err(), "unknown version must reject");
    }

    #[test]
    fn test_decode_rejects_truncated() {
        let session = "truncated-test";
        let instances = vec![make_test_instance(1, session)];
        let acc = make_test_accumulator(1, session);
        let encoded = encode_accumulator(&acc, &instances).expect("encode");

        // Truncate at various offsets
        for len in 0..encoded.len() {
            let result = decode_accumulator(&encoded[..len]);
            assert!(result.is_err(), "truncated at len={len} must reject");
        }
    }

    #[test]
    fn test_decode_rejects_wrong_commitment_len() {
        let mut bad = Vec::new();
        bad.extend_from_slice(&ACCUMULATOR_VERSION.to_be_bytes());
        bad.extend_from_slice(&params_digest());
        bad.extend_from_slice(&1u32.to_be_bytes()); // fold_depth = 1
                                                    // Wrong commitment length: 100 instead of 26624
        let fake_commit_len = 100u32;
        bad.extend_from_slice(&fake_commit_len.to_be_bytes());
        bad.extend_from_slice(&vec![0u8; 100]);
        // rest doesn't matter, decode should catch it at commitment length
        let result = decode_accumulator(&bad);
        assert!(result.is_err(), "wrong commitment length must reject");
    }

    #[test]
    fn test_decode_rejects_wrong_public_io_len() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ACCUMULATOR_VERSION.to_be_bytes());
        bytes.extend_from_slice(&params_digest());
        bytes.extend_from_slice(&1u32.to_be_bytes()); // fold_depth
                                                      // Valid commitment
        let clen = AJTAI_COMMITMENT_BYTES as u32;
        bytes.extend_from_slice(&clen.to_be_bytes());
        bytes.extend_from_slice(&vec![0u8; AJTAI_COMMITMENT_BYTES]);
        // Wrong public io length: 31 instead of 32
        bytes.extend_from_slice(&31u32.to_be_bytes());
        bytes.extend_from_slice(&vec![0u8; 31]);
        let result = decode_accumulator(&bytes);
        assert!(result.is_err(), "wrong public_io length must reject");
    }

    #[test]
    fn test_decode_rejects_depth_mismatch() {
        let session = "depth-test";
        let instances = vec![make_test_instance(1, session)];
        let mut acc = make_test_accumulator(1, session);
        // Set fold_depth mismatched with instance_count
        acc.fold_depth = 3; // claims 3 folds but only 1 instance
        let result = encode_accumulator(&acc, &instances);
        assert!(result.is_err(), "depth mismatch must be rejected at encode");
    }

    #[test]
    fn test_decode_rejects_norm_bound_exceeded() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ACCUMULATOR_VERSION.to_be_bytes());
        bytes.extend_from_slice(&params_digest());
        bytes.extend_from_slice(&1u32.to_be_bytes()); // fold_depth
                                                      // Valid commitment
        let clen = AJTAI_COMMITMENT_BYTES as u32;
        bytes.extend_from_slice(&clen.to_be_bytes());
        bytes.extend_from_slice(&vec![0u8; AJTAI_COMMITMENT_BYTES]);
        // Valid public io
        bytes.extend_from_slice(&32u32.to_be_bytes());
        bytes.extend_from_slice(&vec![0u8; 32]);
        // norm_bound_current exceeds beta_at_t (1344)
        bytes.extend_from_slice(&(PVTHFHE_CYCLO_PARAMS.beta_at_t + 1).to_be_bytes());
        // session_id
        bytes.extend_from_slice(&4u32.to_be_bytes());
        bytes.extend_from_slice(b"test");
        // instance_count = 1
        bytes.extend_from_slice(&1u32.to_be_bytes());
        // per-instance section (98 bytes)
        bytes.extend_from_slice(&1u16.to_be_bytes()); // pid
        bytes.extend_from_slice(&[0u8; 32]); // ajtai hash
        bytes.extend_from_slice(&[0u8; 32]); // public_io hash
        bytes.extend_from_slice(&[0u8; 32]); // sha256_binding

        let result = decode_accumulator(&bytes);
        assert!(
            result.is_err(),
            "norm_bound_current exceeding beta_at_t must reject"
        );
    }

    #[test]
    fn test_empty_accumulator_roundtrip() {
        let session = "empty-test";
        let instances: Vec<CcsPShareInstance> = vec![];
        let acc = CycloAccumulator {
            fold_depth: 0,
            acc_commitment_bytes: vec![0u8; AJTAI_COMMITMENT_BYTES],
            acc_public_io_bytes: vec![0u8; 32],
            norm_bound_current: PVTHFHE_CYCLO_PARAMS.norm_bound_b,
            session_id: session.to_string(),
            params_digest: params_digest(),
        };

        let encoded = encode_accumulator(&acc, &instances).expect("encode empty");
        let (decoded_acc, decoded_refs) = decode_accumulator(&encoded).expect("decode empty");

        assert_eq!(decoded_acc.fold_depth, 0);
        assert_eq!(decoded_refs.len(), 0);
    }

    #[test]
    fn test_decode_rejects_wrong_params_digest() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ACCUMULATOR_VERSION.to_be_bytes());
        // Wrong params digest
        bytes.extend_from_slice(&[0xFFu8; 32]);
        bytes.extend_from_slice(&0u32.to_be_bytes()); // fold_depth
                                                      // valid commitment
        let clen = AJTAI_COMMITMENT_BYTES as u32;
        bytes.extend_from_slice(&clen.to_be_bytes());
        bytes.extend_from_slice(&vec![0u8; AJTAI_COMMITMENT_BYTES]);
        // valid public io
        bytes.extend_from_slice(&32u32.to_be_bytes());
        bytes.extend_from_slice(&vec![0u8; 32]);
        // valid norm_bound
        bytes.extend_from_slice(&PVTHFHE_CYCLO_PARAMS.norm_bound_b.to_be_bytes());
        // session_id
        bytes.extend_from_slice(&0u32.to_be_bytes()); // empty session
                                                      // instance_count = 0
        bytes.extend_from_slice(&0u32.to_be_bytes());

        let result = decode_accumulator(&bytes);
        assert!(result.is_err(), "wrong params_digest must reject");
    }

    #[test]
    fn test_decode_rejects_duplicate_participant_ids() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ACCUMULATOR_VERSION.to_be_bytes());
        bytes.extend_from_slice(&params_digest());
        bytes.extend_from_slice(&2u32.to_be_bytes()); // fold_depth = 2
                                                      // Valid commitment
        let clen = AJTAI_COMMITMENT_BYTES as u32;
        bytes.extend_from_slice(&clen.to_be_bytes());
        bytes.extend_from_slice(&vec![0u8; AJTAI_COMMITMENT_BYTES]);
        // Valid public io
        bytes.extend_from_slice(&32u32.to_be_bytes());
        bytes.extend_from_slice(&vec![0u8; 32]);
        // valid norm_bound
        bytes.extend_from_slice(&PVTHFHE_CYCLO_PARAMS.beta_at_t.to_be_bytes());
        // session_id
        bytes.extend_from_slice(&3u32.to_be_bytes());
        bytes.extend_from_slice(b"dup");
        // instance_count = 2
        bytes.extend_from_slice(&2u32.to_be_bytes());
        // Instance 1: pid=1
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&[1u8; 32]);
        bytes.extend_from_slice(&[1u8; 32]);
        bytes.extend_from_slice(&[1u8; 32]);
        // Instance 2: pid=1 (duplicate!)
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&[2u8; 32]);
        bytes.extend_from_slice(&[2u8; 32]);
        bytes.extend_from_slice(&[2u8; 32]);

        let result = decode_accumulator(&bytes);
        assert!(result.is_err(), "duplicate participant IDs must reject");
    }
}
