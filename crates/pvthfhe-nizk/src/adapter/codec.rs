//! Byte-level codec for the Cyclo NIZK proof envelope: little-endian/big-endian
//! field encoders, the sigma-section round codec, the ternary-challenge encoding,
//! and the proof [`Cursor`] reader.

use crate::ajtai::AjtaiCommitment;
use crate::sigma;
use crate::{NizkError, NizkStatement};

use pvthfhe_cyclo::accumulator_codec;

use super::PROOF_VERSION;

fn encode_u64s_le(out: &mut Vec<u8>, vals: &[u64]) -> Result<(), NizkError> {
    let len = u32::try_from(vals.len()).map_err(|_| NizkError::InvalidInput {
        reason: "encode_u64s_le: too many values",
        party_id: None,
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    for &v in vals {
        out.extend_from_slice(&v.to_le_bytes());
    }
    Ok(())
}

fn encode_i64s_le(out: &mut Vec<u8>, vals: &[i64]) -> Result<(), NizkError> {
    let len = u32::try_from(vals.len()).map_err(|_| NizkError::InvalidInput {
        reason: "encode_i64s_le: too many values",
        party_id: None,
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    for &v in vals {
        out.extend_from_slice(&v.to_le_bytes());
    }
    Ok(())
}

pub(super) fn encode_proof_multi(
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
    let sid_len = u32::try_from(sid_bytes.len()).map_err(|_| NizkError::InvalidInput {
        reason: "session_id too long",
        party_id: Some(stmt.participant_id),
    })?;
    out.extend_from_slice(&sid_len.to_be_bytes());
    out.extend_from_slice(sid_bytes);
    out.extend_from_slice(&stmt.participant_id.to_be_bytes());
    out.extend_from_slice(hash_commitment);

    let mut sigma_section = Vec::new();
    encode_u64s_le(&mut sigma_section, d_rns)?;
    // Encode round count followed by per-round proofs
    let num_rounds =
        u32::try_from(sigma_multi.rounds.len()).map_err(|_| NizkError::InvalidInput {
            reason: "too many sigma rounds",
            party_id: Some(stmt.participant_id),
        })?;
    sigma_section.extend_from_slice(&num_rounds.to_be_bytes());
    for proof in &sigma_multi.rounds {
        encode_u64s_le(&mut sigma_section, &proof.t_rns)?;
        encode_i64s_le(&mut sigma_section, &proof.z_s)?;
        encode_i64s_le(&mut sigma_section, &proof.z_e)?;
        encode_ch_ternary_32(&mut sigma_section, proof.ch)?;
    }

    let sigma_len = u32::try_from(sigma_section.len()).map_err(|_| NizkError::InvalidInput {
        reason: "sigma section too large",
        party_id: Some(stmt.participant_id),
    })?;
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
        return Err(NizkError::InvalidInput {
            reason: "proof too short for accumulator placeholder",
            party_id: None,
        });
    }
    let old_len = proof_bytes.len();
    proof_bytes.truncate(old_len - 4);

    let acc_transcript = accumulator_codec::encode_accumulator(acc, instances).map_err(|_| {
        NizkError::InvalidInput {
            reason: "accumulator transcript encode failed",
            party_id: None,
        }
    })?;

    let acc_len = u32::try_from(acc_transcript.len()).map_err(|_| NizkError::InvalidInput {
        reason: "accumulator transcript too large",
        party_id: None,
    })?;
    proof_bytes.extend_from_slice(&acc_len.to_be_bytes());
    proof_bytes.extend_from_slice(&acc_transcript);
    Ok(())
}

pub(super) fn decode_sigma_section_multi(
    bytes: &[u8],
) -> Result<(Vec<u64>, sigma::SigmaMultiProof), NizkError> {
    let mut cur = Cursor::new(bytes);
    let d_rns = cur.read_u64s()?;
    let num_rounds = usize::try_from(cur.read_u32()?).map_err(|_| NizkError::InvalidProof {
        reason: "sigma round count overflow",
        party_id: None,
    })?;
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
        _ => {
            return Err(NizkError::InvalidInput {
                reason: "challenge must be -1, 0, or 1",
                party_id: None,
            })
        }
    };
    let mut encoded = [fill; 32];
    encoded[..8].copy_from_slice(&ch.to_le_bytes());
    out.extend_from_slice(&encoded);
    Ok(())
}

pub(super) struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(super) fn read_exact(&mut self, len: usize) -> Result<&'a [u8], NizkError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(NizkError::InvalidProof {
                reason: "proof length overflow",
                party_id: None,
            })?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(NizkError::InvalidProof {
                reason: "truncated proof bytes",
                party_id: None,
            })?;
        self.offset = end;
        Ok(slice)
    }

    pub(super) fn skip(&mut self, len: usize) -> Result<(), NizkError> {
        self.read_exact(len)?;
        Ok(())
    }

    pub(super) fn read_u16(&mut self) -> Result<u16, NizkError> {
        let b: [u8; 2] = self
            .read_exact(2)?
            .try_into()
            .map_err(|_| NizkError::InvalidProof {
                reason: "bad u16",
                party_id: None,
            })?;
        Ok(u16::from_be_bytes(b))
    }

    pub(super) fn read_u32(&mut self) -> Result<u32, NizkError> {
        let b: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| NizkError::InvalidProof {
                reason: "bad u32",
                party_id: None,
            })?;
        Ok(u32::from_be_bytes(b))
    }

    pub(super) fn read_len_prefixed_bytes(&mut self) -> Result<Vec<u8>, NizkError> {
        let len = usize::try_from(self.read_u32()?).map_err(|_| NizkError::InvalidProof {
            reason: "length overflows usize",
            party_id: None,
        })?;
        Ok(self.read_exact(len)?.to_vec())
    }

    fn read_u64s(&mut self) -> Result<Vec<u64>, NizkError> {
        let count = usize::try_from(self.read_u32()?).map_err(|_| NizkError::InvalidProof {
            reason: "u64s count overflows usize",
            party_id: None,
        })?;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let b: [u8; 8] =
                self.read_exact(8)?
                    .try_into()
                    .map_err(|_| NizkError::InvalidProof {
                        reason: "bad u64",
                        party_id: None,
                    })?;
            out.push(u64::from_le_bytes(b));
        }
        Ok(out)
    }

    fn read_i64s(&mut self) -> Result<Vec<i64>, NizkError> {
        let count = usize::try_from(self.read_u32()?).map_err(|_| NizkError::InvalidProof {
            reason: "i64s count overflows usize",
            party_id: None,
        })?;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let b: [u8; 8] =
                self.read_exact(8)?
                    .try_into()
                    .map_err(|_| NizkError::InvalidProof {
                        reason: "bad i64",
                        party_id: None,
                    })?;
            out.push(i64::from_le_bytes(b));
        }
        Ok(out)
    }

    fn read_ch_ternary_32(&mut self) -> Result<i64, NizkError> {
        let bytes = self.read_exact(32)?;
        let low: [u8; 8] = bytes[..8].try_into().map_err(|_| NizkError::InvalidProof {
            reason: "bad challenge scalar",
            party_id: None,
        })?;
        let ch = i64::from_le_bytes(low);
        let expected_fill = match ch {
            -1 => 0xff,
            0 | 1 => 0x00,
            _ => {
                return Err(NizkError::InvalidProof {
                    reason: "challenge must be -1, 0, or 1",
                    party_id: None,
                })
            }
        };
        if bytes[8..].iter().any(|&b| b != expected_fill) {
            return Err(NizkError::InvalidProof {
                reason: "non-canonical challenge scalar",
                party_id: None,
            });
        }
        Ok(ch)
    }

    pub(super) fn finish(self) -> Result<(), NizkError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(NizkError::InvalidProof {
                reason: "trailing proof bytes",
                party_id: None,
            })
        }
    }
}
