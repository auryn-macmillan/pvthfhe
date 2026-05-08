use std::sync::Arc;

use pvthfhe_fhe::{
    error::FheError,
    fhers::FhersBackend,
    types::PublicKey,
    FheBackend,
};
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};

use crate::nizk_share::{
    compute_ciphertext_v, compute_share_commitment, ShareNizkProof, ShareNizkProver,
    ShareNizkStatement, ShareNizkVerifier, ShareNizkWitness,
};
use crate::nizk_decrypt::{
    DecryptNizkProof, DecryptNizkProver, DecryptNizkStatement, DecryptNizkVerifier,
    DecryptNizkWitness,
};
use crate::{DecryptedShare, EncryptedShares, PvssAdapter, PvssContext, PvssError};

const BACKEND_ID: &str = "lattice-pvss-bfv-d2";
const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";
const SHARE_RANDOMNESS_LABEL: &[u8] = b"pvss-share-randomness-v1";

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
        };
        let proof = DecryptNizkProver::prove(&statement, witness)?;

        Ok(DecryptedShare {
            index: party_index,
            share_bytes: decrypted_share_bytes,
            proof: proof.proof_bytes,
        })
    }

    fn verify_decrypted_share(&self, share: &DecryptedShare) -> Result<(), PvssError> {
        let proof = DecryptNizkProof::from_bytes(share.proof.clone())?;
        let opened = proof.decode()?;
        if opened.statement.party_index != share.index
            || opened.statement.decrypted_share_bytes != share.share_bytes
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

        let shares = shamir_split(secret, ctx)?;
        let mut ciphertexts = Vec::with_capacity(ctx.n);
        let mut proofs = Vec::with_capacity(ctx.n);

        for (index, (share_bytes, recipient_pk_bytes)) in shares
            .iter()
            .zip(recipient_pks.iter())
            .enumerate()
        {
            let recipient_pk = PublicKey {
                bytes: recipient_pk_bytes.clone(),
            };
            let mut rng = ChaCha8Rng::from_seed(derive_seed(secret, ctx, index));
            let ciphertext_u = self
                .backend
                .encrypt(&recipient_pk, share_bytes, &mut rng)
                .map(|ciphertext| ciphertext.bytes)
                .map_err(map_fhe_error)?;

            let share_commitment = compute_share_commitment(&ctx.session_id, index, share_bytes);
            let ciphertext_v = compute_ciphertext_v(&ciphertext_u);
            let statement = ShareNizkStatement {
                session_id: ctx.session_id.clone(),
                dealer_index: 0,
                recipient_index: index,
                recipient_pk: recipient_pk_bytes.clone(),
                ciphertext_u: ciphertext_u.clone(),
                ciphertext_v: ciphertext_v.to_vec(),
                share_commitment: share_commitment.to_vec(),
            };
            let witness = ShareNizkWitness {
                share_bytes: share_bytes.clone(),
                encryption_randomness: derive_share_randomness(secret, ctx, index, recipient_pk_bytes),
            };
            let proof = ShareNizkProver::prove(&statement, &witness)?;

            ciphertexts.push(ciphertext_u);
            proofs.push(proof.proof_bytes);
        }

        Ok(EncryptedShares {
            ciphertexts,
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
                session_id: ctx.session_id.clone(),
                dealer_index: opened.statement.dealer_index,
                recipient_index: index,
                recipient_pk: opened.statement.recipient_pk.clone(),
                ciphertext_u: ciphertext_u.clone(),
                ciphertext_v: compute_ciphertext_v(ciphertext_u).to_vec(),
                share_commitment: compute_share_commitment(&ctx.session_id, index, &opened.share_bytes).to_vec(),
            };

            ShareNizkVerifier::verify(&statement, &proof)?;
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
        let share_len = selected
            .first()
            .map(|share| share.share_bytes.len())
            .ok_or(PvssError::RecoveryFailed)?;
        if selected
            .iter()
            .any(|share| share.index >= ctx.n || share.share_bytes.len() != share_len)
        {
            return Err(PvssError::InvalidShare);
        }
        for share in selected {
            self.verify_decrypted_share(share)?;
        }

        let mut seen = vec![false; ctx.n];
        let x_coordinates = selected
            .iter()
            .map(|share| {
                if seen[share.index] {
                    return Err(PvssError::InvalidShare);
                }
                seen[share.index] = true;
                u8::try_from(share.index + 1).map_err(|_| PvssError::RecoveryFailed)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut recovered = vec![0u8; share_len];
        for byte_index in 0..share_len {
            let mut value = 0u8;
            for (share_position, share) in selected.iter().enumerate() {
                let coefficient = lagrange_coefficient_at_zero(share_position, &x_coordinates)
                    .ok_or(PvssError::RecoveryFailed)?;
                value ^= gf256_mul(share.share_bytes[byte_index], coefficient);
            }
            recovered[byte_index] = value;
        }

        Ok(recovered)
    }

    fn backend_id(&self) -> &'static str {
        BACKEND_ID
    }
}

fn validate_context(ctx: &PvssContext) -> Result<(), PvssError> {
    const MAX_N: usize = u8::MAX as usize; // = 255; Shamir over GF(256)
    if ctx.n > MAX_N {
        return Err(PvssError::BackendError(format!(
            "invalid PVSS context: n={} exceeds maximum supported parties {} (Shamir over GF(256))",
            ctx.n, MAX_N
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

fn shamir_split(secret: &[u8], ctx: &PvssContext) -> Result<Vec<Vec<u8>>, PvssError> {
    let mut rng = ChaCha8Rng::from_seed(derive_seed(secret, ctx, ctx.n));
    let mut shares = vec![vec![0u8; secret.len()]; ctx.n];

    for (byte_index, secret_byte) in secret.iter().copied().enumerate() {
        let mut coefficients = vec![0u8; ctx.t];
        coefficients[0] = secret_byte;
        for coefficient in coefficients.iter_mut().skip(1) {
            *coefficient = next_nonzero_byte(&mut rng);
        }

        for (share_index, share_bytes) in shares.iter_mut().enumerate() {
            let x = u8::try_from(share_index + 1).map_err(|_| PvssError::RecoveryFailed)?;
            share_bytes[byte_index] = evaluate_polynomial(&coefficients, x);
        }
    }

    Ok(shares)
}

fn derive_seed(secret: &[u8], ctx: &PvssContext, domain: usize) -> [u8; 32] {
    let mut seed = [0u8; 32];

    for (index, byte) in ctx.session_id.iter().copied().enumerate() {
        seed[index % 32] ^= byte;
        seed[(index * 7 + domain) % 32] = seed[(index * 7 + domain) % 32].wrapping_add(byte);
    }
    for (index, byte) in secret.iter().copied().enumerate() {
        seed[index % 32] ^= byte.rotate_left((index % 8) as u32);
        seed[(index * 11 + domain + 1) % 32] ^= byte.wrapping_add(domain as u8);
    }
    seed[0] ^= ctx.n as u8;
    seed[1] ^= ctx.t as u8;
    seed[2] ^= domain as u8;

    seed
}

fn derive_share_randomness(
    secret: &[u8],
    ctx: &PvssContext,
    recipient_index: usize,
    recipient_pk: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(SHARE_RANDOMNESS_LABEL);
    hasher.update(&ctx.session_id);
    hasher.update(recipient_index.to_be_bytes());
    hasher.update(recipient_pk);
    hasher.update(secret);
    hasher.finalize().to_vec()
}

fn next_nonzero_byte(rng: &mut ChaCha8Rng) -> u8 {
    let mut byte = 0u8;
    while byte == 0 {
        byte = (rng.next_u32() & 0xff) as u8;
    }
    byte
}

fn evaluate_polynomial(coefficients: &[u8], x: u8) -> u8 {
    coefficients
        .iter()
        .rev()
        .copied()
        .fold(0u8, |acc, coefficient| gf256_mul(acc, x) ^ coefficient)
}

fn lagrange_coefficient_at_zero(index: usize, x_coordinates: &[u8]) -> Option<u8> {
    let x_i = *x_coordinates.get(index)?;
    let mut numerator = 1u8;
    let mut denominator = 1u8;

    for (other_index, x_j) in x_coordinates.iter().copied().enumerate() {
        if other_index == index {
            continue;
        }
        numerator = gf256_mul(numerator, x_j);
        denominator = gf256_mul(denominator, x_i ^ x_j);
    }

    gf256_inverse(denominator).map(|inverse| gf256_mul(numerator, inverse))
}

fn gf256_mul(mut left: u8, mut right: u8) -> u8 {
    let mut product = 0u8;
    while right != 0 {
        if right & 1 == 1 {
            product ^= left;
        }
        let carry = left & 0x80;
        left <<= 1;
        if carry != 0 {
            left ^= 0x1b;
        }
        right >>= 1;
    }
    product
}

fn gf256_pow(mut base: u8, mut exponent: u8) -> u8 {
    let mut result = 1u8;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = gf256_mul(result, base);
        }
        base = gf256_mul(base, base);
        exponent >>= 1;
    }
    result
}

fn gf256_inverse(value: u8) -> Option<u8> {
    if value == 0 {
        None
    } else {
        Some(gf256_pow(value, 254))
    }
}

fn map_fhe_error(error: FheError) -> PvssError {
    PvssError::BackendError(error.to_string())
}
