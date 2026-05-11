use std::sync::Arc;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use pvthfhe_fhe::{
    error::FheError,
    fhers::FhersBackend,
    types::PublicKey,
    FheBackend,
};
use pvthfhe_rng::OsRng;
use pvthfhe_types::{EncRandomness, ProtocolBytes, ShareSecret};
use rand_core::RngCore;

use crate::nizk_share::{
    compute_ciphertext_v, compute_share_commitment, ShareNizkProof, ShareNizkProver,
    ShareNizkStatement, ShareNizkVerifier, ShareNizkWitness,
};
use crate::nizk_decrypt::{
    DecryptNizkProof, DecryptNizkProver, DecryptNizkStatement, DecryptNizkVerifier,
    DecryptNizkWitness,
};
use crate::shamir;
use crate::{DecryptedShare, EncryptedShares, PvssAdapter, PvssContext, PvssError};

const BACKEND_ID: &str = "lattice-pvss-bfv-d2";
const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

/// Maximum bytes that fit losslessly into a single BN254 scalar field element.
/// BN254 `Fr` modulus ≈ 2^254, so 31 bytes (248 bits) always fit below the
/// modulus. The caller (`deal`) chunks larger secrets into 31-byte pieces.
const FR_CHUNK_BYTES: usize = 31;

/// Number of bytes in the serialized representation of one `Fr` element.
/// `BigInt<4>` → 4 × u64 = 32 bytes, fixed width by construction.
const FR_SERIALIZED_LEN: usize = 32;

/// Bytes of length prefix prepended to serialized share payloads so that
/// `recover` can reconstruct the original secret byte-length.
const LENGTH_PREFIX_LEN: usize = 4;

/// Sanity cap on the number of parties (prevents memory exhaustion from
/// accidentally huge `n` values; the BN254 scalar field supports far more).
const MAX_PARTIES: usize = 65535;

/// Per-recipient BFV-backed PVSS adapter.
#[derive(Clone)]
pub struct LatticePvssBfvAdapter {
    backend: Arc<dyn FheBackend>,
}

impl core::fmt::Debug for LatticePvssBfvAdapter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LatticePvssBfvAdapter")
            .field("backend_id", &BACKEND_ID)
            .finish()
    }
}

impl Default for LatticePvssBfvAdapter {
    fn default() -> Self {
        Self::new().expect("canonical BFV params must load")
    }
}

impl LatticePvssBfvAdapter {
    /// Construct the adapter with the locked real BFV backend.
    pub fn new() -> Result<Self, PvssError> {
        let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).map_err(map_fhe_error)?;
        Ok(Self::new_with_backend(backend))
    }

    /// Construct the adapter with an injected backend for tests.
    pub fn new_with_backend<B>(backend: B) -> Self
    where
        B: FheBackend + 'static,
    {
        Self {
            backend: Arc::new(backend),
        }
    }

    /// Wrap a decrypted share with a deterministic decrypt-side proof.
    pub fn prove_decrypted_share(
        &self,
        ciphertext_u: &[u8],
        party_pk: &[u8],
        party_index: usize,
        decrypted_share_bytes: Vec<u8>,
        witness: &DecryptNizkWitness,
        ctx: &PvssContext,
    ) -> Result<DecryptedShare, PvssError> {
        let statement = DecryptNizkStatement {
            session_id: ctx.session_id.clone(),
            party_index,
            ciphertext_u: ciphertext_u.to_vec(),
            ciphertext_v: compute_ciphertext_v(ciphertext_u).to_vec(),
            decrypted_share_bytes: decrypted_share_bytes.clone(),
            party_pk: party_pk.to_vec(),
            epoch: ctx.epoch,
        };
        let proof = DecryptNizkProver::prove(&statement, witness)?;

        Ok(DecryptedShare {
            index: party_index,
            share_bytes: ShareSecret::new(decrypted_share_bytes),
            proof: ProtocolBytes(proof.proof_bytes),
        })
    }

    fn verify_decrypted_share(&self, share: &DecryptedShare) -> Result<(), PvssError> {
        let proof = DecryptNizkProof::from_bytes(share.proof.0.clone())?;
        let opened = proof.decode()?;
        if opened.statement.party_index != share.index
            || opened.statement.decrypted_share_bytes != share.share_bytes.expose()
        {
            return Err(PvssError::InvalidShare);
        }

        DecryptNizkVerifier::verify(&opened.statement, &proof)
    }
}

impl PvssAdapter for LatticePvssBfvAdapter {
    fn deal(
        &self,
        secret: &[u8],
        recipient_pks: &[Vec<u8>],
        ctx: &PvssContext,
    ) -> Result<EncryptedShares, PvssError> {
        validate_context(ctx)?;
        if recipient_pks.len() != ctx.n {
            return Err(PvssError::InvalidShare);
        }

        // Convert the raw secret bytes into BN254 scalar field elements.
        // Chunk size of 31 bytes guarantees lossless embedding (2^248 < Fr modulus).
        let secret_frs = secret_to_frs(secret);
        let num_chunks = secret_frs.len();

        // For each chunk, produce a separate Shamir sharing.
        // Collect per-party share Fr values keyed by party index.
        let mut rng = OsRng;
        let mut party_shares: Vec<Vec<Fr>> = vec![Vec::with_capacity(num_chunks); ctx.n];

        for secret_fr in &secret_frs {
            let chunk_shares = shamir::split(secret_fr, ctx.n, ctx.t, &mut rng);
            for (x, share_value) in chunk_shares {
                // x is 1-based index; convert to 0-based for the per-party vectors.
                party_shares[x - 1].push(share_value);
            }
        }

        // Serialize each party's vector of Fr elements into a single byte blob.
        // Format: [ original_len: u32 BE ][ fr_0: 32 bytes ][ fr_1: 32 bytes ]...
        let all_share_bytes: Vec<Vec<u8>> = party_shares
            .iter()
            .map(|shares| serialize_share_payload(shares, secret.len()))
            .collect();

        let mut ciphertexts = Vec::with_capacity(ctx.n);
        let mut proofs = Vec::with_capacity(ctx.n);

        for (index, (share_bytes, recipient_pk_bytes)) in all_share_bytes
            .iter()
            .zip(recipient_pks.iter())
            .enumerate()
        {
            let recipient_pk = PublicKey {
                bytes: recipient_pk_bytes.clone(),
            };
            let mut rng = OsRng;
            let ciphertext_u = self
                .backend
                .encrypt(&recipient_pk, share_bytes, &mut rng)
                .map(|ciphertext| ciphertext.bytes)
                .map_err(map_fhe_error)?;

            let share_commitment = compute_share_commitment(&ctx.session_id, index, share_bytes);
            let ciphertext_v = compute_ciphertext_v(&ciphertext_u);
            let statement = ShareNizkStatement {
                session_id: ProtocolBytes(ctx.session_id.clone()),
                dealer_index: 0,
                recipient_index: index,
                recipient_pk: ProtocolBytes(recipient_pk_bytes.clone()),
                ciphertext_u: ProtocolBytes(ciphertext_u.clone()),
                ciphertext_v: ProtocolBytes(ciphertext_v.to_vec()),
                share_commitment: ProtocolBytes(share_commitment.to_vec()),
            };
            let mut randomness = [0u8; 32];
            OsRng.fill_bytes(&mut randomness);
            let witness = ShareNizkWitness {
                share_bytes: ShareSecret::new(share_bytes.clone()),
                encryption_randomness: EncRandomness::new(randomness.to_vec()),
            };
            let proof = ShareNizkProver::prove(self.backend.as_ref(), &statement, &witness)?;

            ciphertexts.push(ciphertext_u);
            proofs.push(proof.proof_bytes.0);
        }

        Ok(EncryptedShares {
            ciphertexts,
            share_bytes: all_share_bytes.clone(),
            proofs,
            backend_id: BACKEND_ID.to_owned(),
        })
    }

    fn verify_shares(&self, shares: &EncryptedShares, ctx: &PvssContext) -> Result<(), PvssError> {
        validate_context(ctx)?;
        if shares.backend_id != BACKEND_ID {
            return Err(PvssError::InvalidShare);
        }
        if shares.ciphertexts.len() != ctx.n || shares.proofs.len() != ctx.n {
            return Err(PvssError::InvalidShare);
        }

        for (index, (ciphertext_u, proof_bytes)) in shares
            .ciphertexts
            .iter()
            .zip(shares.proofs.iter())
            .enumerate()
        {
            let proof = ShareNizkProof::from_bytes(proof_bytes.clone())?;
            let opened = proof.decode()?;
            let statement = ShareNizkStatement {
                session_id: ProtocolBytes(ctx.session_id.clone()),
                dealer_index: opened.statement.dealer_index,
                recipient_index: index,
                recipient_pk: opened.statement.recipient_pk.clone(),
                ciphertext_u: ProtocolBytes(ciphertext_u.clone()),
                ciphertext_v: ProtocolBytes(compute_ciphertext_v(ciphertext_u).to_vec()),
                share_commitment: opened.statement.share_commitment.clone(),
            };

            ShareNizkVerifier::verify(self.backend.as_ref(), &statement, &proof)?;
        }
        Ok(())
    }

    fn recover(
        &self,
        decrypted_shares: &[DecryptedShare],
        ctx: &PvssContext,
    ) -> Result<Vec<u8>, PvssError> {
        validate_context(ctx)?;
        if decrypted_shares.len() < ctx.t {
            return Err(PvssError::RecoveryFailed);
        }

        let selected = &decrypted_shares[..ctx.t];

        // Validate share payload consistency.
        if selected.is_empty() {
            return Err(PvssError::RecoveryFailed);
        }
        let share_len = selected[0].share_bytes.expose().len();
        if share_len < LENGTH_PREFIX_LEN + FR_SERIALIZED_LEN {
            return Err(PvssError::InvalidShare);
        }
        // Shares must all have identical length.
        if selected
            .iter()
            .any(|share| share.share_bytes.expose().len() != share_len)
        {
            return Err(PvssError::InvalidShare);
        }
        // Share indices must be in-bounds.
        if selected.iter().any(|share| share.index >= ctx.n) {
            return Err(PvssError::InvalidShare);
        }

        // Verify NIZK proofs.
        for share in selected {
            self.verify_decrypted_share(share)?;
        }

        // Check for duplicate indices.
        let mut seen = vec![false; ctx.n];
        for share in selected {
            if seen[share.index] {
                return Err(PvssError::InvalidShare);
            }
            seen[share.index] = true;
        }

        // Parse each share's payload into its component Fr values.
        // Payload format: [ original_len: u32 BE ][ fr_0: 32 bytes ][ fr_1: 32 bytes ]...
        let (original_len, share_frs_by_party) = deserialize_share_payloads(selected)?;
        let num_chunks = share_frs_by_party[0].len();
        if num_chunks == 0 {
            return Err(PvssError::InvalidShare);
        }

        // Recover each chunk independently via Lagrange interpolation.
        let mut recovered_frs = Vec::with_capacity(num_chunks);
        for chunk_idx in 0..num_chunks {
            let chunk_shares: Vec<(usize, Fr)> = share_frs_by_party
                .iter()
                .enumerate()
                .map(|(i, party_frs)| {
                    // x-coordinate = 1-based share index.
                    (selected[i].index + 1, party_frs[chunk_idx])
                })
                .collect();

            let recovered = shamir::recover(&chunk_shares).map_err(|_| {
                PvssError::RecoveryFailed
            })?;
            recovered_frs.push(recovered);
        }

        // Convert recovered Fr elements back to the original byte form.
        Ok(frs_to_secret(&recovered_frs, original_len))
    }

    fn backend_id(&self) -> &'static str {
        BACKEND_ID
    }
}

// ── context validation ─────────────────────────────────────────────────

fn validate_context(ctx: &PvssContext) -> Result<(), PvssError> {
    if ctx.n > MAX_PARTIES {
        return Err(PvssError::BackendError(format!(
            "invalid PVSS context: n={} exceeds maximum supported parties {}",
            ctx.n, MAX_PARTIES
        )));
    }
    if ctx.n == 0 || ctx.t == 0 || ctx.t > ctx.n {
        return Err(PvssError::BackendError(format!(
            "invalid PVSS context: n={}, t={}",
            ctx.n, ctx.t
        )));
    }
    Ok(())
}

// ── secret ↔ Fr conversion ─────────────────────────────────────────────

/// Split arbitrary bytes into 31-byte padded chunks and convert each chunk
/// into a BN254 scalar field element.
///
/// Each chunk is zero-padded to 32 bytes, interpreted as a little-endian u256,
/// and converted to `Fr` via the canonical `BigInt` path (NOT via
/// `from_le_bytes_mod_order`, so values ≥ modulus are rejected).  Since each
/// chunk contains at most 31 bytes of actual data (248 bits), the resulting
/// integer is always strictly less than the BN254 scalar modulus.
fn secret_to_frs(secret: &[u8]) -> Vec<Fr> {
    let num_chunks = secret.len().div_ceil(FR_CHUNK_BYTES);
    let mut frs = Vec::with_capacity(num_chunks);

    for chunk_bytes in secret.chunks(FR_CHUNK_BYTES) {
        let mut padded = [0u8; FR_SERIALIZED_LEN];
        padded[..chunk_bytes.len()].copy_from_slice(chunk_bytes);
        let fr = bytes32_to_fr(&padded).expect("31 data bytes always < Fr modulus");
        frs.push(fr);
    }

    frs
}

/// Reconstruct the original secret bytes from recovered `Fr` elements.
///
/// Each `Fr` is serialized to a fixed 32-byte representation and truncated to
/// 31 data-bearing bytes. The result is then sliced to `original_len`.
fn frs_to_secret(frs: &[Fr], original_len: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(original_len);

    for fr in frs {
        let bytes = fr_to_bytes32(fr);
        let take = FR_CHUNK_BYTES.min(original_len - result.len());
        result.extend_from_slice(&bytes[..take]);
        if result.len() >= original_len {
            break;
        }
    }

    result.truncate(original_len);
    result
}

/// Serialize an `Fr` element to a fixed 32-byte little-endian representation
/// by extracting the 4 × u64 limbs of the underlying `BigInt<4>`.
fn fr_to_bytes32(fr: &Fr) -> [u8; FR_SERIALIZED_LEN] {
    let bigint: ark_ff::BigInt<4> = fr.into_bigint();
    let mut bytes = [0u8; FR_SERIALIZED_LEN];
    for (i, limb) in bigint.0.iter().enumerate() {
        let start = i * 8;
        bytes[start..start + 8].copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

/// Deserialize a 32-byte slice into an `Fr` element.
///
/// Returns `None` if the encoded integer is ≥ the BN254 scalar modulus.
fn bytes32_to_fr(bytes: &[u8; FR_SERIALIZED_LEN]) -> Option<Fr> {
    let mut limbs = [0u64; 4];
    for (i, chunk) in bytes.chunks_exact(8).enumerate() {
        limbs[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    let bigint = ark_ff::BigInt::<4>::new(limbs);
    Fr::from_bigint(bigint)
}

// ── share payload serialization ─────────────────────────────────────────

/// Serialize a per-party vector of `Fr` values into a byte blob for FHE
/// encryption.
///
/// Payload format (all fields little-endian):
///
/// ```text
/// ┌──────────────────┬──────────────────┬─────────────┬──────────────────┐
/// │ original_len     │ fr_0             │ fr_1        │  …               │
/// │ (4 bytes, BE)    │ (32 bytes, LE)   │ (32 bytes)  │                  │
/// └──────────────────┴──────────────────┴─────────────┴──────────────────┘
/// ```
fn serialize_share_payload(share_frs: &[Fr], original_len: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        LENGTH_PREFIX_LEN + share_frs.len() * FR_SERIALIZED_LEN,
    );
    let len_bytes = (original_len as u32).to_be_bytes();
    payload.extend_from_slice(&len_bytes);
    for fr in share_frs {
        payload.extend_from_slice(&fr_to_bytes32(fr));
    }
    payload
}

/// Parse the share payloads from a set of decrypted shares, returning the
/// original secret length and a vector-per-party of recovered `Fr` values.
///
/// All parties' payloads must have the identical structure.
fn deserialize_share_payloads(
    selected: &[DecryptedShare],
) -> Result<(usize, Vec<Vec<Fr>>), PvssError> {
    let first_payload = selected[0].share_bytes.expose();
    let original_len = u32::from_be_bytes(
        first_payload[..LENGTH_PREFIX_LEN]
            .try_into()
            .map_err(|_| PvssError::InvalidShare)?,
    ) as usize;

    let num_chunks = (first_payload.len() - LENGTH_PREFIX_LEN) / FR_SERIALIZED_LEN;
    if (first_payload.len() - LENGTH_PREFIX_LEN) % FR_SERIALIZED_LEN != 0 {
        return Err(PvssError::InvalidShare);
    }

    for share in selected.iter().skip(1) {
        let payload = share.share_bytes.expose();
        if payload.len() != first_payload.len() {
            return Err(PvssError::InvalidShare);
        }
        let len = u32::from_be_bytes(
            payload[..LENGTH_PREFIX_LEN]
                .try_into()
                .map_err(|_| PvssError::InvalidShare)?,
        ) as usize;
        if len != original_len {
            return Err(PvssError::InvalidShare);
        }
    }

    let mut share_frs_by_party = Vec::with_capacity(selected.len());
    for share in selected {
        let payload = share.share_bytes.expose();
        let mut frs = Vec::with_capacity(num_chunks);
        for chunk_start in
            (LENGTH_PREFIX_LEN..payload.len()).step_by(FR_SERIALIZED_LEN)
        {
            let chunk: &[u8; FR_SERIALIZED_LEN] = payload[chunk_start..chunk_start + FR_SERIALIZED_LEN]
                .try_into()
                .map_err(|_| PvssError::InvalidShare)?;
            let fr = bytes32_to_fr(chunk).ok_or(PvssError::InvalidShare)?;
            frs.push(fr);
        }
        share_frs_by_party.push(frs);
    }

    Ok((original_len, share_frs_by_party))
}

// ── helpers ─────────────────────────────────────────────────────────────

fn map_fhe_error(error: FheError) -> PvssError {
    PvssError::BackendError(error.to_string())
}
