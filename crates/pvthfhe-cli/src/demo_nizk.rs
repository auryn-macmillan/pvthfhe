//! Shared demo NIZK input construction for pvthfhe-cli binaries and tests.

use anyhow::Context;
use pvthfhe_aggregator::keygen::types::Round1Message;
use pvthfhe_fhe::real_nizk::{NizkStatement, NizkWitness};
use pvthfhe_rng::OsRng;
use rand::RngCore;

/// Build the demo NIZK statement and witness used by the CLI binaries.
///
/// `seed` controls the witness RNG: `None` uses secure `OsRng`; `Some(s)`
/// requires the `demo-seeded-rng` feature flag (Stage 0 tripwire).
///
/// `secret_key_bytes` should be the output of `FhersBackend::party_secret_key_bytes()`
/// for the party identified by `message.party_id`.
pub fn build_demo_nizk_inputs(
    session_id: &str,
    message: &Round1Message,
    seed: Option<u64>,
    secret_key_bytes: &[u8],
) -> anyhow::Result<(NizkStatement, NizkWitness)> {
    let participant_id = u16::try_from(message.party_id)
        .with_context(|| format!("party id {} does not fit u16", message.party_id))?;

    let secret_share = if secret_key_bytes.len() >= 8 {
        u64::from_le_bytes(secret_key_bytes[..8].try_into().expect("slice len 8"))
    } else {
        let mut buf = [0u8; 8];
        let len = secret_key_bytes.len().min(8);
        buf[..len].copy_from_slice(&secret_key_bytes[..len]);
        u64::from_le_bytes(buf)
    };

    let secret_share_poly = bytes_to_i64_poly(secret_key_bytes);

    let mut witness_rng: Box<dyn RngCore> = match seed {
        Some(s) => {
            #[cfg(not(feature = "demo-seeded-rng"))]
            {
                let _ = s;
                tracing::warn!(
                    "demo_nizk: seed={} ignored (demo-seeded-rng feature not enabled); \
                     falling back to OsRng for secure randomness",
                    s
                );
                Box::new(OsRng)
            }
            #[cfg(feature = "demo-seeded-rng")]
            {
                use rand::SeedableRng;
                Box::new(rand::rngs::StdRng::seed_from_u64(
                    s ^ u64::from(message.party_id) ^ 0xD2C1_0A11,
                ))
            }
        }
        None => Box::new(OsRng),
    };

    let mut randomness = vec![0_u8; 32];
    witness_rng.fill_bytes(&mut randomness);

    let pvss_commitment = pvthfhe_pvss::nizk_share::compute_share_commitment(
        session_id.as_bytes(),
        (participant_id as usize).saturating_sub(1),
        secret_key_bytes,
    );

    Ok((
        NizkStatement {
            ciphertext_bytes: message.pk_i.bytes.clone(),
            decrypt_share_bytes: message.commitment.to_vec(),
            pvss_commitment,
            params: (
                65_537_u64,
                pvthfhe_nizk::sigma::RLWE_N,
                pvthfhe_nizk::sigma::B_E as u64,
            ),
            session_id: session_id.to_owned(),
            participant_id,
            epoch: 0,
        },
        NizkWitness {
            secret_share,
            secret_share_poly,
            error: vec![1, -1, 0, 2],
            randomness,
        },
    ))
}

fn bytes_to_i64_poly(bytes: &[u8]) -> Vec<i64> {
    let num_coeffs = bytes.len() / 8;
    let mut poly = Vec::with_capacity(num_coeffs);
    for chunk in bytes.chunks_exact(8) {
        let arr: [u8; 8] = chunk.try_into().expect("chunk is 8 bytes");
        poly.push(i64::from_le_bytes(arr));
    }
    poly
}
