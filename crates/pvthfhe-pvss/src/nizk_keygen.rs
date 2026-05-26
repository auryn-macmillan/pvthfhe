pub struct KeygenNizkProof {
    pub proof_bytes: Vec<u8>,
}

pub fn prove_keygen_nizk(
    pk0_bytes: &[u8],
    pk1_bytes: &[u8],
    sk_coeffs: &[i64],
    e_coeffs: &[i64],
    session_id: &[u8],
    party_id: u32,
    rng: &mut dyn rand_core::RngCore,
) -> Result<KeygenNizkProof, pvthfhe_nizk::NizkError> {
    let c_rns = pvthfhe_nizk::bfv_sigma::poly_bytes_to_rns(pk1_bytes)?;
    let d_rns = pvthfhe_nizk::bfv_sigma::poly_bytes_to_rns(pk0_bytes)?;

    let stmt = pvthfhe_nizk::sigma::SigmaStatement {
        c_rns: c_rns.clone(),
        d_rns: d_rns.clone(),
    };
    let wit = pvthfhe_nizk::sigma::SigmaWitness {
        s_i: sk_coeffs.to_vec(),
        e_i: e_coeffs.to_vec(),
    };

    let d_commitment = compute_keygen_d_commitment(session_id, party_id, pk0_bytes, pk1_bytes);
    let proof = pvthfhe_nizk::sigma::prove(session_id, party_id, &stmt, &wit, rng, &d_commitment)?;

    let mut proof_bytes = Vec::new();
    encode_i64_vec_buf(&proof.z_s, &mut proof_bytes);
    encode_i64_vec_buf(&proof.z_e, &mut proof_bytes);
    encode_u64_vec_buf(&proof.t_rns, &mut proof_bytes);
    proof_bytes.extend_from_slice(&proof.ch.to_le_bytes());

    Ok(KeygenNizkProof { proof_bytes })
}

pub fn verify_keygen_nizk(
    pk0_bytes: &[u8],
    pk1_bytes: &[u8],
    proof: &KeygenNizkProof,
    session_id: &[u8],
    party_id: u32,
) -> Result<(), pvthfhe_nizk::NizkError> {
    use pvthfhe_nizk::{bfv_sigma, sigma};

    let c_rns = bfv_sigma::poly_bytes_to_rns(pk1_bytes)?;
    let d_rns = bfv_sigma::poly_bytes_to_rns(pk0_bytes)?;

    let stmt = sigma::SigmaStatement { c_rns, d_rns };

    let proof_decoded = decode_keygen_proof(&proof.proof_bytes)?;

    let d_commitment = compute_keygen_d_commitment(session_id, party_id, pk0_bytes, pk1_bytes);
    sigma::verify(session_id, party_id, &stmt, &proof_decoded, &d_commitment)
}

fn decode_keygen_proof(
    data: &[u8],
) -> Result<pvthfhe_nizk::sigma::SigmaProof, pvthfhe_nizk::NizkError> {
    use pvthfhe_nizk::NizkError;

    if data.len() < 4 {
        return Err(NizkError::InvalidInput("keygen proof too short"));
    }

    let z_s = decode_i64_vec(data);
    let z_s_size = 4 + z_s.len() * 8;
    if data.len() < z_s_size + 4 {
        return Err(NizkError::InvalidInput("keygen proof truncated at z_s"));
    }

    let z_e = decode_i64_vec(&data[z_s_size..]);
    let z_e_size = 4 + z_e.len() * 8;
    if data.len() < z_s_size + z_e_size + 4 {
        return Err(NizkError::InvalidInput("keygen proof truncated at z_e"));
    }

    let t_offset = z_s_size + z_e_size;
    let t_rns = decode_u64_vec(&data[t_offset..]);
    let t_size = 4 + t_rns.len() * 8;

    let ch_offset = t_offset + t_size;
    if data.len() < ch_offset + 8 {
        return Err(NizkError::InvalidInput("keygen proof truncated at ch"));
    }
    let ch = i64::from_le_bytes(data[ch_offset..ch_offset + 8].try_into().unwrap());

    Ok(pvthfhe_nizk::sigma::SigmaProof {
        z_s,
        z_e,
        t_rns,
        ch,
    })
}

fn compute_keygen_d_commitment(
    session_id: &[u8],
    party_id: u32,
    pk0_bytes: &[u8],
    pk1_bytes: &[u8],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"pvthfhe-keygen-dcommit/v1");
    h.update(session_id);
    h.update(&party_id.to_le_bytes());
    h.update(pk0_bytes);
    h.update(pk1_bytes);
    h.finalize().into()
}

fn encode_i64_vec_buf(v: &[i64], buf: &mut Vec<u8>) {
    buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
    for &val in v {
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

fn encode_u64_vec_buf(v: &[u64], buf: &mut Vec<u8>) {
    buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
    for &val in v {
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

fn decode_i64_vec(data: &[u8]) -> Vec<i64> {
    if data.len() < 4 {
        return vec![];
    }
    let len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
    let elem_bytes = len.min((data.len() - 4) / 8) * 8;
    let mut out = Vec::with_capacity(len);
    for i in 0..(elem_bytes / 8) {
        let bytes = &data[4 + i * 8..4 + (i + 1) * 8];
        out.push(i64::from_le_bytes(bytes.try_into().unwrap()));
    }
    out.resize(len, 0);
    out
}

fn decode_u64_vec(data: &[u8]) -> Vec<u64> {
    if data.len() < 4 {
        return vec![];
    }
    let len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
    let elem_bytes = len.min((data.len() - 4) / 8) * 8;
    let mut out = Vec::with_capacity(len);
    for i in 0..(elem_bytes / 8) {
        let bytes = &data[4 + i * 8..4 + (i + 1) * 8];
        out.push(u64::from_le_bytes(bytes.try_into().unwrap()));
    }
    out.resize(len, 0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_proof_roundtrip() {
        let z_s = vec![1i64, -2, 3];
        let z_e = vec![4i64, -5, 6];
        let t_rns = vec![7u64, 8, 9];
        let ch = 1i64;

        let mut buf = Vec::new();
        encode_i64_vec_buf(&z_s, &mut buf);
        encode_i64_vec_buf(&z_e, &mut buf);
        encode_u64_vec_buf(&t_rns, &mut buf);
        buf.extend_from_slice(&ch.to_le_bytes());

        let proof = KeygenNizkProof { proof_bytes: buf };
        let decoded = decode_keygen_proof(&proof.proof_bytes).unwrap();
        assert_eq!(decoded.z_s, vec![1i64, -2, 3]);
        assert_eq!(decoded.z_e, vec![4i64, -5, 6]);
        assert_eq!(&decoded.t_rns[..3], &[7u64, 8, 9]);
        assert_eq!(decoded.ch, 1i64);
    }
}
