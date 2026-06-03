//! Canonical verification statement encoding and Poseidon-BN254 hashing.
//!
//! This module defines the Phase-1 statement anchor shared by Rust, Noir, and
//! later Solidity. Every 32-byte value is split into two big-endian 128-bit
//! limbs before Poseidon absorption; reducing 256-bit values modulo BN254 Fr is
//! intentionally rejected because it would be non-injective.

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use light_poseidon::parameters::bn254_x5;
use light_poseidon::PoseidonParameters;
use serde::{Deserialize, Serialize};

/// ASCII domain separator for the V1 canonical statement format.
pub const DOMAIN_BYTES: &[u8] = b"pvthfhe-verification-stmt-v1";
/// DOMAIN_BYTES interpreted as one big-endian integer; it fits in BN254 Fr.
pub const DOMAIN_FIELD_HEX: &str = "0x707674686668652d766572696669636174696f6e2d73746d742d7631";
/// Schema version encoded in the TLV header and Poseidon preimage.
pub const SCHEMA_VERSION: u32 = 1;
/// Number of fields in VerificationStatementV1.
pub const FIELD_COUNT: u32 = 19;
/// Fixed Poseidon preimage length: 3 header elements + 3 numerics*3 + 16 roots*4.
pub const POSEIDON_PREIMAGE_LEN: usize = 76;

/// Rust Noir-sponge replica / Noir parity hash for the committed golden vector.
pub const GOLDEN_STATEMENT_HASH_DECIMAL: &str =
    "2717525839999002672616025848791696639911259589570414897881626410761076250408";
/// Hex rendering of [`GOLDEN_STATEMENT_HASH_DECIMAL`].
pub const GOLDEN_STATEMENT_HASH_HEX: &str =
    "0x060210ab9a90369d1ed6dd70d8687f5a82ba942418742add1569ba42fd329728";

/// Error returned by canonical statement parsing or hashing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationStatementError {
    /// Byte encoding violated the V1 TLV schema.
    InvalidFormat(&'static str),
    /// Input ended before a complete header/field could be read.
    Truncated,
    /// Bytes remained after the last declared field.
    TrailingBytes,
    /// Poseidon construction or hashing failed.
    Poseidon(String),
}

impl core::fmt::Display for VerificationStatementError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidFormat(msg) => write!(f, "invalid verification statement: {msg}"),
            Self::Truncated => f.write_str("truncated verification statement"),
            Self::TrailingBytes => f.write_str("trailing bytes after verification statement"),
            Self::Poseidon(msg) => write!(f, "Poseidon hash failed: {msg}"),
        }
    }
}

impl std::error::Error for VerificationStatementError {}

/// The canonical public verification statement consumed by all verifier surfaces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationStatementV1 {
    pub protocol_version: u32,
    pub context_id: [u8; 32],
    pub dkg_root: [u8; 32],
    pub epoch: u64,
    pub participant_set_hash: [u8; 32],
    pub aggregate_pk_hash: [u8; 32],
    pub ciphertext_hash: [u8; 32],
    pub plaintext_hash: [u8; 32],
    pub d_commitment: [u8; 32],
    pub c5_proof_root: [u8; 32],
    pub c6_proof_set_root: [u8; 32],
    pub cyclo_accumulator_root: [u8; 32],
    pub ivc_vk_hash: [u8; 32],
    pub ivc_pp_hash: [u8; 32],
    pub ivc_proof_hash: [u8; 32],
    pub z0_commitment: [u8; 32],
    pub zi_commitment: [u8; 32],
    pub ivc_steps: u64,
    pub bootstrap_result_hash: [u8; 32],
}

/// Statement hash rendered in decimal and canonical lowercase hex.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatementHash {
    pub decimal: String,
    pub hex: String,
}

/// Complete golden vector payload for downstream ports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationStatementGoldenFixture {
    pub canonical_bytes_hex: String,
    pub poseidon_preimage_decimal: Vec<String>,
    pub poseidon_preimage_hex: Vec<String>,
    pub statement_hash_decimal: &'static str,
    pub statement_hash_hex: &'static str,
}

impl VerificationStatementV1 {
    /// Encode as canonical TLV bytes.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, VerificationStatementError> {
        let mut out = Vec::new();
        encode_len_prefixed(&mut out, DOMAIN_BYTES)?;
        out.extend_from_slice(&SCHEMA_VERSION.to_be_bytes());
        out.extend_from_slice(&FIELD_COUNT.to_be_bytes());

        encode_tlv(&mut out, 1, &self.protocol_version.to_be_bytes())?;
        encode_tlv(&mut out, 2, &self.context_id)?;
        encode_tlv(&mut out, 3, &self.dkg_root)?;
        encode_tlv(&mut out, 4, &self.epoch.to_be_bytes())?;
        encode_tlv(&mut out, 5, &self.participant_set_hash)?;
        encode_tlv(&mut out, 6, &self.aggregate_pk_hash)?;
        encode_tlv(&mut out, 7, &self.ciphertext_hash)?;
        encode_tlv(&mut out, 8, &self.plaintext_hash)?;
        encode_tlv(&mut out, 9, &self.d_commitment)?;
        encode_tlv(&mut out, 10, &self.c5_proof_root)?;
        encode_tlv(&mut out, 11, &self.c6_proof_set_root)?;
        encode_tlv(&mut out, 12, &self.cyclo_accumulator_root)?;
        encode_tlv(&mut out, 13, &self.ivc_vk_hash)?;
        encode_tlv(&mut out, 14, &self.ivc_pp_hash)?;
        encode_tlv(&mut out, 15, &self.ivc_proof_hash)?;
        encode_tlv(&mut out, 16, &self.z0_commitment)?;
        encode_tlv(&mut out, 17, &self.zi_commitment)?;
        encode_tlv(&mut out, 18, &self.ivc_steps.to_be_bytes())?;
        encode_tlv(&mut out, 19, &self.bootstrap_result_hash)?;
        Ok(out)
    }

    /// Decode canonical TLV bytes, rejecting wrong count/order/ids/lengths/trailing bytes.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, VerificationStatementError> {
        let mut cur = Cursor::new(bytes);
        let domain = cur.read_len_prefixed_bytes()?;
        if domain != DOMAIN_BYTES {
            return Err(VerificationStatementError::InvalidFormat("wrong domain"));
        }
        if cur.read_u32()? != SCHEMA_VERSION {
            return Err(VerificationStatementError::InvalidFormat(
                "wrong schema version",
            ));
        }
        if cur.read_u32()? != FIELD_COUNT {
            return Err(VerificationStatementError::InvalidFormat(
                "wrong field count",
            ));
        }

        let protocol_version = read_u32_field(&mut cur, 1)?;
        let context_id = read_32_field(&mut cur, 2)?;
        let dkg_root = read_32_field(&mut cur, 3)?;
        let epoch = read_u64_field(&mut cur, 4)?;
        let participant_set_hash = read_32_field(&mut cur, 5)?;
        let aggregate_pk_hash = read_32_field(&mut cur, 6)?;
        let ciphertext_hash = read_32_field(&mut cur, 7)?;
        let plaintext_hash = read_32_field(&mut cur, 8)?;
        let d_commitment = read_32_field(&mut cur, 9)?;
        let c5_proof_root = read_32_field(&mut cur, 10)?;
        let c6_proof_set_root = read_32_field(&mut cur, 11)?;
        let cyclo_accumulator_root = read_32_field(&mut cur, 12)?;
        let ivc_vk_hash = read_32_field(&mut cur, 13)?;
        let ivc_pp_hash = read_32_field(&mut cur, 14)?;
        let ivc_proof_hash = read_32_field(&mut cur, 15)?;
        let z0_commitment = read_32_field(&mut cur, 16)?;
        let zi_commitment = read_32_field(&mut cur, 17)?;
        let ivc_steps = read_u64_field(&mut cur, 18)?;
        let bootstrap_result_hash = read_32_field(&mut cur, 19)?;
        cur.finish()?;

        Ok(Self {
            protocol_version,
            context_id,
            dkg_root,
            epoch,
            participant_set_hash,
            aggregate_pk_hash,
            ciphertext_hash,
            plaintext_hash,
            d_commitment,
            c5_proof_root,
            c6_proof_set_root,
            cyclo_accumulator_root,
            ivc_vk_hash,
            ivc_pp_hash,
            ivc_proof_hash,
            z0_commitment,
            zi_commitment,
            ivc_steps,
            bootstrap_result_hash,
        })
    }

    /// Return the exact 76-element Poseidon preimage.
    pub fn poseidon_preimage(&self) -> Vec<Fr> {
        let mut out = Vec::with_capacity(POSEIDON_PREIMAGE_LEN);
        out.push(domain_field());
        out.push(Fr::from(SCHEMA_VERSION as u64));
        out.push(Fr::from(FIELD_COUNT as u64));

        push_numeric(&mut out, 1, 4, self.protocol_version as u64);
        push_bytes32(&mut out, 2, &self.context_id);
        push_bytes32(&mut out, 3, &self.dkg_root);
        push_numeric(&mut out, 4, 8, self.epoch);
        push_bytes32(&mut out, 5, &self.participant_set_hash);
        push_bytes32(&mut out, 6, &self.aggregate_pk_hash);
        push_bytes32(&mut out, 7, &self.ciphertext_hash);
        push_bytes32(&mut out, 8, &self.plaintext_hash);
        push_bytes32(&mut out, 9, &self.d_commitment);
        push_bytes32(&mut out, 10, &self.c5_proof_root);
        push_bytes32(&mut out, 11, &self.c6_proof_set_root);
        push_bytes32(&mut out, 12, &self.cyclo_accumulator_root);
        push_bytes32(&mut out, 13, &self.ivc_vk_hash);
        push_bytes32(&mut out, 14, &self.ivc_pp_hash);
        push_bytes32(&mut out, 15, &self.ivc_proof_hash);
        push_bytes32(&mut out, 16, &self.z0_commitment);
        push_bytes32(&mut out, 17, &self.zi_commitment);
        push_numeric(&mut out, 18, 8, self.ivc_steps);
        push_bytes32(&mut out, 19, &self.bootstrap_result_hash);

        assert_eq!(out.len(), POSEIDON_PREIMAGE_LEN);
        out
    }

    /// Compute Poseidon BN254 hash using the same `new_circom` style as pvthfhe-nizk.
    pub fn statement_hash(&self) -> Result<StatementHash, VerificationStatementError> {
        hash_preimage(&self.poseidon_preimage())
    }

    /// Test-only negative variant: swap every 32-byte field's hi and lo limbs.
    pub fn statement_hash_with_swapped_hi_lo_limbs(
        &self,
    ) -> Result<StatementHash, VerificationStatementError> {
        let mut preimage = self.poseidon_preimage();
        let mut offset = 3;
        for field_id in 1..=19 {
            if matches!(field_id, 1 | 4 | 18) {
                offset += 3;
            } else {
                preimage.swap(offset + 2, offset + 3);
                offset += 4;
            }
        }
        hash_preimage(&preimage)
    }

    /// Test-only negative variant: parse 16-byte limbs as little-endian integers.
    pub fn statement_hash_with_little_endian_limbs(
        &self,
    ) -> Result<StatementHash, VerificationStatementError> {
        let mut out = Vec::with_capacity(POSEIDON_PREIMAGE_LEN);
        out.push(domain_field());
        out.push(Fr::from(SCHEMA_VERSION as u64));
        out.push(Fr::from(FIELD_COUNT as u64));

        push_numeric(&mut out, 1, 4, self.protocol_version as u64);
        push_bytes32_le_limbs(&mut out, 2, &self.context_id);
        push_bytes32_le_limbs(&mut out, 3, &self.dkg_root);
        push_numeric(&mut out, 4, 8, self.epoch);
        push_bytes32_le_limbs(&mut out, 5, &self.participant_set_hash);
        push_bytes32_le_limbs(&mut out, 6, &self.aggregate_pk_hash);
        push_bytes32_le_limbs(&mut out, 7, &self.ciphertext_hash);
        push_bytes32_le_limbs(&mut out, 8, &self.plaintext_hash);
        push_bytes32_le_limbs(&mut out, 9, &self.d_commitment);
        push_bytes32_le_limbs(&mut out, 10, &self.c5_proof_root);
        push_bytes32_le_limbs(&mut out, 11, &self.c6_proof_set_root);
        push_bytes32_le_limbs(&mut out, 12, &self.cyclo_accumulator_root);
        push_bytes32_le_limbs(&mut out, 13, &self.ivc_vk_hash);
        push_bytes32_le_limbs(&mut out, 14, &self.ivc_pp_hash);
        push_bytes32_le_limbs(&mut out, 15, &self.ivc_proof_hash);
        push_bytes32_le_limbs(&mut out, 16, &self.z0_commitment);
        push_bytes32_le_limbs(&mut out, 17, &self.zi_commitment);
        push_numeric(&mut out, 18, 8, self.ivc_steps);
        push_bytes32_le_limbs(&mut out, 19, &self.bootstrap_result_hash);
        hash_preimage(&out)
    }

    /// Test-only negative variant: reduce each 32-byte value mod Fr as one element.
    pub fn statement_hash_with_mod_p_reduction(
        &self,
    ) -> Result<StatementHash, VerificationStatementError> {
        let mut out = Vec::new();
        out.push(domain_field());
        out.push(Fr::from(SCHEMA_VERSION as u64));
        out.push(Fr::from(FIELD_COUNT as u64));

        push_numeric(&mut out, 1, 4, self.protocol_version as u64);
        push_bytes32_mod_p(&mut out, 2, &self.context_id);
        push_bytes32_mod_p(&mut out, 3, &self.dkg_root);
        push_numeric(&mut out, 4, 8, self.epoch);
        push_bytes32_mod_p(&mut out, 5, &self.participant_set_hash);
        push_bytes32_mod_p(&mut out, 6, &self.aggregate_pk_hash);
        push_bytes32_mod_p(&mut out, 7, &self.ciphertext_hash);
        push_bytes32_mod_p(&mut out, 8, &self.plaintext_hash);
        push_bytes32_mod_p(&mut out, 9, &self.d_commitment);
        push_bytes32_mod_p(&mut out, 10, &self.c5_proof_root);
        push_bytes32_mod_p(&mut out, 11, &self.c6_proof_set_root);
        push_bytes32_mod_p(&mut out, 12, &self.cyclo_accumulator_root);
        push_bytes32_mod_p(&mut out, 13, &self.ivc_vk_hash);
        push_bytes32_mod_p(&mut out, 14, &self.ivc_pp_hash);
        push_bytes32_mod_p(&mut out, 15, &self.ivc_proof_hash);
        push_bytes32_mod_p(&mut out, 16, &self.z0_commitment);
        push_bytes32_mod_p(&mut out, 17, &self.zi_commitment);
        push_numeric(&mut out, 18, 8, self.ivc_steps);
        push_bytes32_mod_p(&mut out, 19, &self.bootstrap_result_hash);
        hash_preimage(&out)
    }

    /// Generate the Rust golden vector fixture.
    pub fn golden_fixture() -> Result<VerificationStatementGoldenFixture, VerificationStatementError>
    {
        let statement = golden_statement();
        let preimage = statement.poseidon_preimage();
        Ok(VerificationStatementGoldenFixture {
            canonical_bytes_hex: hex_encode(&statement.encode_canonical()?),
            poseidon_preimage_decimal: field_elements_to_decimal_strings(&preimage),
            poseidon_preimage_hex: field_elements_to_hex_strings(&preimage),
            statement_hash_decimal: GOLDEN_STATEMENT_HASH_DECIMAL,
            statement_hash_hex: GOLDEN_STATEMENT_HASH_HEX,
        })
    }
}

/// Field elements rendered as canonical decimal integers.
pub fn field_elements_to_decimal_strings(values: &[Fr]) -> Vec<String> {
    values.iter().map(fr_to_decimal).collect()
}

/// Field elements rendered as lowercase `0x` hex integers.
pub fn field_elements_to_hex_strings(values: &[Fr]) -> Vec<String> {
    values.iter().map(fr_to_hex).collect()
}

fn golden_statement() -> VerificationStatementV1 {
    fn bytes(seed: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        out
    }

    VerificationStatementV1 {
        protocol_version: 1,
        context_id: bytes(0x10),
        dkg_root: bytes(0x20),
        epoch: 42,
        participant_set_hash: bytes(0x30),
        aggregate_pk_hash: bytes(0x40),
        ciphertext_hash: bytes(0x50),
        plaintext_hash: bytes(0x60),
        d_commitment: bytes(0x70),
        c5_proof_root: bytes(0x80),
        c6_proof_set_root: bytes(0x90),
        cyclo_accumulator_root: bytes(0xa0),
        ivc_vk_hash: bytes(0xb0),
        ivc_pp_hash: bytes(0xc0),
        ivc_proof_hash: bytes(0xd0),
        z0_commitment: bytes(0xe0),
        zi_commitment: bytes(0xf0),
        ivc_steps: 7,
        bootstrap_result_hash: bytes(0x08),
    }
}

fn hash_preimage(inputs: &[Fr]) -> Result<StatementHash, VerificationStatementError> {
    let hash = noir_bn254_sponge(inputs)?;
    Ok(StatementHash {
        decimal: fr_to_decimal(&hash),
        hex: fr_to_hex(&hash),
    })
}

pub fn noir_bn254_sponge(inputs: &[Fr]) -> Result<Fr, VerificationStatementError> {
    let params = bn254_x5::get_poseidon_parameters::<Fr>(5).map_err(|err| {
        VerificationStatementError::Poseidon(format!("x5_5 params failed: {err}"))
    })?;
    let mut state = vec![Fr::zero(); 5];
    let mut rate_offset = 0usize;

    for input in inputs {
        state[1 + rate_offset] += input;
        rate_offset += 1;
        if rate_offset == 4 {
            poseidon_permute(&params, &mut state);
            rate_offset = 0;
        }
    }
    if rate_offset != 0 {
        poseidon_permute(&params, &mut state);
    }

    Ok(state[1])
}

fn poseidon_permute(params: &PoseidonParameters<Fr>, state: &mut Vec<Fr>) {
    let all_rounds = params.full_rounds + params.partial_rounds;
    let half_rounds = params.full_rounds / 2;

    for round in 0..half_rounds {
        apply_ark(params, state, round);
        apply_sbox_full(params, state);
        apply_mds(params, state);
    }

    for round in half_rounds..half_rounds + params.partial_rounds {
        apply_ark(params, state, round);
        state[0] = state[0].pow([params.alpha]);
        apply_mds(params, state);
    }

    for round in half_rounds + params.partial_rounds..all_rounds {
        apply_ark(params, state, round);
        apply_sbox_full(params, state);
        apply_mds(params, state);
    }
}

fn apply_ark(params: &PoseidonParameters<Fr>, state: &mut [Fr], round: usize) {
    for (i, value) in state.iter_mut().enumerate() {
        *value += params.ark[round * params.width + i];
    }
}

fn apply_sbox_full(params: &PoseidonParameters<Fr>, state: &mut [Fr]) {
    for value in state {
        *value = value.pow([params.alpha]);
    }
}

fn apply_mds(params: &PoseidonParameters<Fr>, state: &mut Vec<Fr>) {
    *state = state
        .iter()
        .enumerate()
        .map(|(i, _)| {
            state
                .iter()
                .enumerate()
                .fold(Fr::zero(), |acc, (j, value)| {
                    acc + *value * params.mds[i][j]
                })
        })
        .collect();
}

fn domain_field() -> Fr {
    fr_from_be_bytes(DOMAIN_BYTES)
}

fn push_numeric(out: &mut Vec<Fr>, field_id: u16, byte_len: u32, value: u64) {
    out.push(Fr::from(field_id as u64));
    out.push(Fr::from(byte_len as u64));
    out.push(Fr::from(value));
}

fn push_bytes32(out: &mut Vec<Fr>, field_id: u16, bytes: &[u8; 32]) {
    out.push(Fr::from(field_id as u64));
    out.push(Fr::from(32u64));
    out.push(fr_from_be_bytes(&bytes[..16]));
    out.push(fr_from_be_bytes(&bytes[16..]));
}

fn push_bytes32_le_limbs(out: &mut Vec<Fr>, field_id: u16, bytes: &[u8; 32]) {
    out.push(Fr::from(field_id as u64));
    out.push(Fr::from(32u64));
    out.push(fr_from_le_bytes_no_reduction(&bytes[..16]));
    out.push(fr_from_le_bytes_no_reduction(&bytes[16..]));
}

fn push_bytes32_mod_p(out: &mut Vec<Fr>, field_id: u16, bytes: &[u8; 32]) {
    out.push(Fr::from(field_id as u64));
    out.push(Fr::from(32u64));
    out.push(Fr::from_be_bytes_mod_order(bytes));
}

fn fr_from_be_bytes(bytes: &[u8]) -> Fr {
    let mut le = [0u8; 32];
    for (i, b) in bytes.iter().rev().enumerate() {
        le[i] = *b;
    }
    Fr::from_le_bytes_mod_order(&le)
}

fn fr_from_le_bytes_no_reduction(bytes: &[u8]) -> Fr {
    let mut le = [0u8; 32];
    le[..bytes.len()].copy_from_slice(bytes);
    Fr::from_le_bytes_mod_order(&le)
}

fn fr_to_decimal(value: &Fr) -> String {
    value.into_bigint().to_string()
}

fn fr_to_hex(value: &Fr) -> String {
    let bytes = value.into_bigint().to_bytes_be();
    let first_nonzero = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    format!("0x{}", hex_encode(&bytes[first_nonzero..]))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn encode_len_prefixed(out: &mut Vec<u8>, data: &[u8]) -> Result<(), VerificationStatementError> {
    let len = u32::try_from(data.len())
        .map_err(|_| VerificationStatementError::InvalidFormat("length exceeds u32"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

fn encode_tlv(
    out: &mut Vec<u8>,
    field_id: u16,
    value: &[u8],
) -> Result<(), VerificationStatementError> {
    let len = u32::try_from(value.len())
        .map_err(|_| VerificationStatementError::InvalidFormat("field length exceeds u32"))?;
    out.extend_from_slice(&field_id.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn read_u32_field(
    cur: &mut Cursor<'_>,
    expected_id: u16,
) -> Result<u32, VerificationStatementError> {
    let bytes = read_field(cur, expected_id, 4)?;
    let arr: [u8; 4] = bytes
        .try_into()
        .map_err(|_| VerificationStatementError::InvalidFormat("invalid u32 field"))?;
    Ok(u32::from_be_bytes(arr))
}

fn read_u64_field(
    cur: &mut Cursor<'_>,
    expected_id: u16,
) -> Result<u64, VerificationStatementError> {
    let bytes = read_field(cur, expected_id, 8)?;
    let arr: [u8; 8] = bytes
        .try_into()
        .map_err(|_| VerificationStatementError::InvalidFormat("invalid u64 field"))?;
    Ok(u64::from_be_bytes(arr))
}

fn read_32_field(
    cur: &mut Cursor<'_>,
    expected_id: u16,
) -> Result<[u8; 32], VerificationStatementError> {
    let bytes = read_field(cur, expected_id, 32)?;
    bytes
        .try_into()
        .map_err(|_| VerificationStatementError::InvalidFormat("invalid bytes32 field"))
}

fn read_field<'a>(
    cur: &mut Cursor<'a>,
    expected_id: u16,
    expected_len: usize,
) -> Result<&'a [u8], VerificationStatementError> {
    let id = cur.read_u16()?;
    if id != expected_id {
        return Err(VerificationStatementError::InvalidFormat(
            "wrong field id/order",
        ));
    }
    let len = usize::try_from(cur.read_u32()?)
        .map_err(|_| VerificationStatementError::InvalidFormat("field length overflows usize"))?;
    if len != expected_len {
        return Err(VerificationStatementError::InvalidFormat(
            "wrong field length",
        ));
    }
    cur.read_exact(len)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], VerificationStatementError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(VerificationStatementError::Truncated)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(VerificationStatementError::Truncated)?;
        self.offset = end;
        Ok(slice)
    }

    fn read_u16(&mut self) -> Result<u16, VerificationStatementError> {
        let b: [u8; 2] = self
            .read_exact(2)?
            .try_into()
            .map_err(|_| VerificationStatementError::Truncated)?;
        Ok(u16::from_be_bytes(b))
    }

    fn read_u32(&mut self) -> Result<u32, VerificationStatementError> {
        let b: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| VerificationStatementError::Truncated)?;
        Ok(u32::from_be_bytes(b))
    }

    fn read_len_prefixed_bytes(&mut self) -> Result<Vec<u8>, VerificationStatementError> {
        let len = usize::try_from(self.read_u32()?)
            .map_err(|_| VerificationStatementError::InvalidFormat("length overflows usize"))?;
        Ok(self.read_exact(len)?.to_vec())
    }

    fn finish(self) -> Result<(), VerificationStatementError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(VerificationStatementError::TrailingBytes)
        }
    }
}
