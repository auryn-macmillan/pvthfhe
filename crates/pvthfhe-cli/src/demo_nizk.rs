//! Shared demo NIZK input construction for pvthfhe-cli binaries and tests.

use anyhow::Context;
use pvthfhe_aggregator::keygen::types::Round1Message;
use pvthfhe_fhe::real_nizk::{NizkStatement, NizkWitness};
use rand::rngs::StdRng;
use rand::RngCore;
use rand::SeedableRng;
use sha2::{Digest, Sha256};

/// Build the demo NIZK statement and witness used by the CLI binaries.
pub fn build_demo_nizk_inputs(
    session_id: &str,
    message: &Round1Message,
) -> anyhow::Result<(NizkStatement, NizkWitness)> {
    let participant_id = u16::try_from(message.party_id)
        .with_context(|| format!("party id {} does not fit u16", message.party_id))?;
    let secret_share = demo_secret_share(session_id, participant_id, &message.pk_i.bytes);
    let mut witness_rng = StdRng::seed_from_u64(u64::from(message.party_id) ^ 0xD2C1_0A11);
    let mut randomness = vec![0_u8; 32];
    witness_rng.fill_bytes(&mut randomness);

    Ok((
        NizkStatement {
            ciphertext_bytes: message.pk_i.bytes.clone(),
            decrypt_share_bytes: message.commitment.to_vec(),
            pvss_commitment: demo_pvss_commitment(session_id, participant_id, secret_share),
            params: (
                65_537_u64,
                pvthfhe_nizk::sigma::RLWE_N,
                pvthfhe_nizk::sigma::B_E as u64,
            ),
            session_id: session_id.to_owned(),
            participant_id,
        },
        NizkWitness {
            secret_share,
            secret_share_poly: demo_secret_share_poly(&mut witness_rng),
            error: vec![1, -1, 0, 2],
            randomness,
        },
    ))
}

fn demo_secret_share(session_id: &str, participant_id: u16, pk_bytes: &[u8]) -> u64 {
    let mut binding = Vec::new();
    binding.extend_from_slice(session_id.as_bytes());
    binding.extend_from_slice(&participant_id.to_be_bytes());
    binding.extend_from_slice(pk_bytes);
    let digest = sha256_bytes(&binding);
    u64::from_be_bytes(digest[..8].try_into().expect("digest slice is 8 bytes")) % 65_537
}

fn demo_pvss_commitment(session_id: &str, participant_id: u16, secret_share: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    hasher.update(participant_id.to_le_bytes());
    hasher.update(secret_share.to_be_bytes());
    hasher.finalize().into()
}

fn demo_secret_share_poly(rng: &mut StdRng) -> Vec<i64> {
    let mut poly = vec![0_i64; 8_192];
    poly[0] = 1;
    poly[1] = -1;
    for coeff in poly.iter_mut().skip(2).take(30) {
        *coeff = match rng.next_u32() % 3 {
            0 => -1,
            1 => 0,
            _ => 1,
        };
    }
    poly
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
