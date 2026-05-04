use sha2::{Digest, Sha256};

pub fn params_digest_v1(label: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(label).finalize().into()
}

pub fn challenge_v1(
    session_id: &str,
    fold_depth: u32,
    acc_commitment: &[u8],
    inst_ajtai_bytes: &[u8],
    inst_public_io_bytes: &[u8],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"pvthfhe-cyclo-fs-v1")
        .chain_update(session_id.as_bytes())
        .chain_update(fold_depth.to_le_bytes())
        .chain_update(acc_commitment)
        .chain_update(inst_ajtai_bytes)
        .chain_update(inst_public_io_bytes)
        .finalize()
        .into()
}

pub fn commitment_v1(
    session_id: &str,
    depth: u32,
    poly_bytes: &[u8],
    inst_bytes: &[u8],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"pvthfhe-cyclo-fold-v1")
        .chain_update(session_id.as_bytes())
        .chain_update(depth.to_le_bytes())
        .chain_update(poly_bytes)
        .chain_update(inst_bytes)
        .finalize()
        .into()
}

pub fn public_io_v1(
    session_id: &str,
    depth: u32,
    acc_io: &[u8],
    inst_io: &[u8],
    r_byte: u8,
) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"pvthfhe-cyclo-fold-io-v1")
        .chain_update(session_id.as_bytes())
        .chain_update(depth.to_le_bytes())
        .chain_update(acc_io)
        .chain_update(inst_io)
        .chain_update([r_byte])
        .finalize()
        .into()
}

pub fn init_commitment_v1(session_id: &str, poly_bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"pvthfhe-cyclo-init-v1")
        .chain_update(session_id.as_bytes())
        .chain_update(poly_bytes)
        .finalize()
        .into()
}

pub fn init_public_io_v1(session_id: &str, io_bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"pvthfhe-cyclo-init-io-v1")
        .chain_update(session_id.as_bytes())
        .chain_update(io_bytes)
        .finalize()
        .into()
}
