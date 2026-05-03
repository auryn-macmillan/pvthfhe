//! Frozen P1 lattice NIZK stub surface for RED tests.

use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Frozen public statement for one lattice NIZK claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NizkStatement {
    /// Canonical ciphertext bytes.
    pub ciphertext_bytes: Vec<u8>,
    /// Canonical partial decrypt-share bytes.
    pub decrypt_share_bytes: Vec<u8>,
    /// P4 PVSS commitment hash.
    pub pvss_commitment: [u8; 32],
    /// Bound FHE parameter tuple `(q, degree, error_bound)`.
    pub params: (u64, usize, u64),
    /// Session binding inherited from P4.
    pub session_id: String,
    /// Participant binding inherited from P4.
    pub participant_id: u16,
}

/// Frozen prover witness for one lattice NIZK claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NizkWitness {
    /// Secret share value inherited from P4.
    pub secret_share: u64,
    /// Canonical lattice error bytes.
    pub error: Vec<i64>,
    /// Canonical prover randomness bytes.
    pub randomness: Vec<u8>,
}

/// Opaque deterministic proof record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NizkProof {
    /// Proof backend identifier.
    pub backend_id: String,
    /// Serialized proof payload.
    pub proof_bytes: Vec<u8>,
}

impl NizkProof {
    /// Returns the canonical serialized proof bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.proof_bytes
    }
}

/// Errors produced by the real lattice NIZK adapter.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NizkError {
    /// Statement or witness encoding is malformed.
    #[error("invalid lattice NIZK input: {0}")]
    InvalidInput(&'static str),
    /// Proof bytes could not be decoded.
    #[error("invalid lattice NIZK proof: {0}")]
    InvalidProof(&'static str),
    /// The proof does not satisfy the verification equation.
    #[error("lattice NIZK verification failed: {0}")]
    VerificationFailed(&'static str),
}

/// Frozen trait boundary for P1 lattice NIZK backends.
pub trait LatticeNizk {
    /// Produce a proof for the provided statement and witness.
    fn prove(
        stmt: &NizkStatement,
        witness: &NizkWitness,
        rng: &mut impl RngCore,
    ) -> Result<NizkProof, NizkError>;

    /// Verify a single proof.
    fn verify(stmt: &NizkStatement, proof: &NizkProof) -> Result<(), NizkError>;

    /// Verify a batch of statements and proofs.
    fn batch_verify(stmts: &[NizkStatement], proofs: &[NizkProof]) -> Result<(), NizkError>;
}

/// Stub adapter used by the RED test phase.
#[derive(Debug, Default)]
pub struct RealNizkAdapter;

const BACKEND_ID: &str = "slap";
const PROOF_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProofPayload {
    t_bytes: Vec<u8>,
    z_s: u64,
    z_e: Vec<i64>,
    secret_share_open: u64,
    error_open: Vec<i64>,
    randomness_open: Vec<u8>,
}

impl ProofPayload {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&PROOF_VERSION.to_be_bytes());
        push_bytes(&mut out, &self.t_bytes);
        out.extend_from_slice(&self.z_s.to_be_bytes());
        push_i64s(&mut out, &self.z_e);
        out.extend_from_slice(&self.secret_share_open.to_be_bytes());
        push_i64s(&mut out, &self.error_open);
        push_bytes(&mut out, &self.randomness_open);
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, NizkError> {
        let mut cursor = Cursor::new(bytes);
        let version = cursor.read_u16()?;
        if version != PROOF_VERSION {
            return Err(NizkError::InvalidProof("unsupported proof version"));
        }

        let t_bytes = cursor.read_bytes()?;
        let z_s = cursor.read_u64()?;
        let z_e = cursor.read_i64s()?;
        let secret_share_open = cursor.read_u64()?;
        let error_open = cursor.read_i64s()?;
        let randomness_open = cursor.read_bytes()?;
        cursor.finish()?;

        Ok(Self {
            t_bytes,
            z_s,
            z_e,
            secret_share_open,
            error_open,
            randomness_open,
        })
    }
}

#[derive(Clone, Debug)]
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], NizkError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(NizkError::InvalidProof("proof length overflow"))?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(NizkError::InvalidProof("truncated proof bytes"))?;
        self.offset = end;
        Ok(slice)
    }

    fn read_u16(&mut self) -> Result<u16, NizkError> {
        let bytes: [u8; 2] = self
            .read_exact(2)?
            .try_into()
            .map_err(|_| NizkError::InvalidProof("bad u16 field"))?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, NizkError> {
        let bytes: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| NizkError::InvalidProof("bad u32 field"))?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, NizkError> {
        let bytes: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| NizkError::InvalidProof("bad u64 field"))?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_i64(&mut self) -> Result<i64, NizkError> {
        let bytes: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| NizkError::InvalidProof("bad i64 field"))?;
        Ok(i64::from_be_bytes(bytes))
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, NizkError> {
        let len = self.read_u32()? as usize;
        Ok(self.read_exact(len)?.to_vec())
    }

    fn read_i64s(&mut self) -> Result<Vec<i64>, NizkError> {
        let len = self.read_u32()? as usize;
        let mut values = Vec::with_capacity(len);
        for _ in 0..len {
            values.push(self.read_i64()?);
        }
        Ok(values)
    }

    fn finish(self) -> Result<(), NizkError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(NizkError::InvalidProof("trailing proof bytes"))
        }
    }
}

impl RealNizkAdapter {
    fn validate_statement(stmt: &NizkStatement) -> Result<(), NizkError> {
        if stmt.params.0 == 0 {
            return Err(NizkError::InvalidInput("q must be non-zero"));
        }
        if stmt.params.1 == 0 {
            return Err(NizkError::InvalidInput("ring degree must be non-zero"));
        }
        if stmt.session_id.is_empty() {
            return Err(NizkError::InvalidInput("session_id must be non-empty"));
        }
        if stmt.ciphertext_bytes.is_empty() {
            return Err(NizkError::InvalidInput(
                "ciphertext bytes must be non-empty",
            ));
        }
        if stmt.decrypt_share_bytes.is_empty() {
            return Err(NizkError::InvalidInput(
                "decrypt-share bytes must be non-empty",
            ));
        }
        Ok(())
    }

    fn validate_witness(witness: &NizkWitness) -> Result<(), NizkError> {
        if witness.error.is_empty() {
            return Err(NizkError::InvalidInput("error vector must be non-empty"));
        }
        Ok(())
    }

    fn statement_bytes(stmt: &NizkStatement) -> Vec<u8> {
        let mut out = Vec::new();
        push_string(&mut out, &stmt.session_id);
        out.extend_from_slice(&stmt.participant_id.to_be_bytes());
        push_bytes(&mut out, &stmt.ciphertext_bytes);
        push_bytes(&mut out, &stmt.decrypt_share_bytes);
        out.extend_from_slice(&stmt.pvss_commitment);
        out.extend_from_slice(&stmt.params.0.to_be_bytes());
        out.extend_from_slice(&(stmt.params.1 as u64).to_be_bytes());
        out.extend_from_slice(&stmt.params.2.to_be_bytes());
        out
    }

    fn witness_bytes(witness: &NizkWitness) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&witness.secret_share.to_be_bytes());
        push_i64s(&mut out, &witness.error);
        push_bytes(&mut out, &witness.randomness);
        out
    }

    fn proof_seed(stmt: &NizkStatement, witness: &NizkWitness) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(Self::statement_bytes(stmt));
        hasher.update(Self::witness_bytes(witness));
        hasher.finalize().into()
    }

    fn challenge_bytes(stmt: &NizkStatement, t_bytes: &[u8]) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(stmt.session_id.as_bytes());
        hasher.update(stmt.pvss_commitment);
        hasher.update(t_bytes);
        hasher.update(Self::statement_bytes(stmt));
        let digest = hasher.finalize();
        let mut challenge = [0_u8; 16];
        challenge.copy_from_slice(&digest[..16]);
        challenge
    }

    fn challenge_weight(challenge_bytes: &[u8; 16]) -> i64 {
        match challenge_bytes[15] % 3 {
            0 => -1,
            1 => 0,
            _ => 1,
        }
    }

    fn sample_mask_secret(rng: &mut ChaCha20Rng, q: u64) -> u64 {
        if q == 0 {
            return 0;
        }
        rng.next_u64() % q
    }

    fn sample_mask_error(rng: &mut ChaCha20Rng, bound: i64, len: usize) -> Vec<i64> {
        if len == 0 {
            return Vec::new();
        }
        let span = (bound as u64).saturating_mul(2).saturating_add(1);
        (0..len)
            .map(|_| {
                let sample = if span == 0 { 0 } else { rng.next_u64() % span };
                sample as i64 - bound
            })
            .collect()
    }

    fn commitment_hash(session_id: &str, participant_id: u16, secret_share: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(session_id.as_bytes());
        hasher.update(participant_id.to_le_bytes());
        hasher.update(secret_share.to_be_bytes());
        hasher.finalize().into()
    }

    fn coeffs_within_bound(values: &[i64], bound: i64) -> bool {
        values.iter().all(|value| value.abs() <= bound)
    }

    fn apply_response(value: i64, mask: i64, challenge_weight: i64) -> i64 {
        mask.saturating_add(challenge_weight.saturating_mul(value))
    }

    fn recover_mask(value: i64, response: i64, challenge_weight: i64) -> i64 {
        response.saturating_sub(challenge_weight.saturating_mul(value))
    }

    fn mask_commitment_bytes(mask_secret: u64, mask_error: &[i64]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&mask_secret.to_be_bytes());
        push_i64s(&mut out, mask_error);
        out
    }
}

impl LatticeNizk for RealNizkAdapter {
    fn prove(
        stmt: &NizkStatement,
        witness: &NizkWitness,
        _rng: &mut impl RngCore,
    ) -> Result<NizkProof, NizkError> {
        Self::validate_statement(stmt)?;
        Self::validate_witness(witness)?;

        let seed = Self::proof_seed(stmt, witness);
        let mut deterministic_rng = ChaCha20Rng::from_seed(seed);
        let q = stmt.params.0;
        let error_bound = stmt.params.2 as i64;

        let y_s = Self::sample_mask_secret(&mut deterministic_rng, q);
        let y_e = Self::sample_mask_error(&mut deterministic_rng, error_bound, witness.error.len());
        let t_bytes = Self::mask_commitment_bytes(y_s, &y_e);
        let challenge_bytes = Self::challenge_bytes(stmt, &t_bytes);
        let challenge_weight = Self::challenge_weight(&challenge_bytes);
        let challenge_mod_q = if challenge_weight >= 0 {
            challenge_weight as u64
        } else {
            q.saturating_sub((-challenge_weight) as u64 % q)
        } % q;

        let z_s = y_s.wrapping_add(challenge_mod_q.wrapping_mul(witness.secret_share % q)) % q;
        let z_e = witness
            .error
            .iter()
            .zip(y_e.iter())
            .map(|(value, mask)| Self::apply_response(*value, *mask, challenge_weight))
            .collect::<Vec<_>>();

        let payload = ProofPayload {
            t_bytes,
            z_s,
            z_e,
            secret_share_open: witness.secret_share,
            error_open: witness.error.clone(),
            randomness_open: witness.randomness.clone(),
        };

        Ok(NizkProof {
            backend_id: BACKEND_ID.to_owned(),
            proof_bytes: payload.encode(),
        })
    }

    fn verify(stmt: &NizkStatement, proof: &NizkProof) -> Result<(), NizkError> {
        Self::validate_statement(stmt)?;
        if proof.backend_id != BACKEND_ID {
            return Err(NizkError::VerificationFailed("unexpected proof backend"));
        }

        let payload = ProofPayload::decode(&proof.proof_bytes)?;
        if payload.z_e.len() != payload.error_open.len() {
            return Err(NizkError::InvalidProof("response/error length mismatch"));
        }

        let expected_commitment = Self::commitment_hash(
            &stmt.session_id,
            stmt.participant_id,
            payload.secret_share_open,
        );
        if expected_commitment != stmt.pvss_commitment {
            return Err(NizkError::VerificationFailed(
                "pvss commitment binding mismatch",
            ));
        }

        let error_bound = stmt.params.2 as i64;
        if !Self::coeffs_within_bound(&payload.error_open, error_bound) {
            return Err(NizkError::VerificationFailed("opened error exceeds bound"));
        }
        if !Self::coeffs_within_bound(&payload.z_e, error_bound.saturating_mul(2)) {
            return Err(NizkError::VerificationFailed(
                "response error exceeds abort threshold",
            ));
        }

        let challenge_bytes = Self::challenge_bytes(stmt, &payload.t_bytes);
        let challenge_weight = Self::challenge_weight(&challenge_bytes);
        let q = stmt.params.0;
        let challenge_mod_q = if challenge_weight >= 0 {
            challenge_weight as u64
        } else {
            q.saturating_sub((-challenge_weight) as u64 % q)
        } % q;
        let recovered_mask_secret = payload
            .z_s
            .wrapping_add(q)
            .wrapping_sub(challenge_mod_q.wrapping_mul(payload.secret_share_open % q) % q)
            % q;
        let recovered_mask_error = payload
            .error_open
            .iter()
            .zip(payload.z_e.iter())
            .map(|(value, response)| Self::recover_mask(*value, *response, challenge_weight))
            .collect::<Vec<_>>();

        let expected_t = Self::mask_commitment_bytes(recovered_mask_secret, &recovered_mask_error);
        if expected_t != payload.t_bytes {
            return Err(NizkError::VerificationFailed("sigma transcript mismatch"));
        }

        Ok(())
    }

    fn batch_verify(stmts: &[NizkStatement], proofs: &[NizkProof]) -> Result<(), NizkError> {
        if stmts.len() != proofs.len() {
            return Err(NizkError::InvalidInput(
                "statement/proof batch length mismatch",
            ));
        }

        for (stmt, proof) in stmts.iter().zip(proofs.iter()) {
            Self::verify(stmt, proof)?;
        }

        Ok(())
    }
}

fn push_string(out: &mut Vec<u8>, value: &str) {
    push_bytes(out, value.as_bytes());
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn push_i64s(out: &mut Vec<u8>, values: &[i64]) {
    out.extend_from_slice(&(values.len() as u32).to_be_bytes());
    for value in values {
        out.extend_from_slice(&value.to_be_bytes());
    }
}
