//! Plaintext slot encoding for the fhe.rs BFV backend: byte <-> slot packing
//! and the length-prefixed plaintext layout.

use crate::error::FheError;

/// Packs plaintext bytes into little-endian 2-byte `u64` slots and pads to `degree`.
pub fn bytes_to_slots(input: &[u8], degree: usize) -> Vec<u64> {
    let mut slots = input
        .chunks(2)
        .map(|chunk| {
            let lo = u64::from(chunk[0]);
            let hi = u64::from(*chunk.get(1).unwrap_or(&0)) << 8;
            lo | hi
        })
        .collect::<Vec<_>>();
    slots.resize(degree, 0);
    slots
}

/// Unpacks little-endian 2-byte `u64` slots back into plaintext bytes.
pub fn slots_to_bytes(slots: &[u64], original_len: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(slots.len() * 2);
    for slot in slots {
        bytes.push((slot & 0xff) as u8);
        bytes.push(((slot >> 8) & 0xff) as u8);
    }
    bytes.truncate(original_len);
    bytes
}

pub(super) fn encode_plaintext_slots(
    plaintext: &[u8],
    degree: usize,
) -> Result<Vec<u64>, FheError> {
    let max = degree.saturating_sub(1) * 2;
    if plaintext.len() > max {
        return Err(FheError::PlaintextTooLong {
            max,
            got: plaintext.len(),
        });
    }

    let mut slots = Vec::with_capacity(degree);
    slots.push(
        u64::try_from(plaintext.len()).map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?,
    );
    slots.extend(bytes_to_slots(plaintext, degree.saturating_sub(1)));
    slots.truncate(degree);
    #[cfg(feature = "trace-decrypt")]
    eprintln!(
        "[FHE-ENCODE] plaintext_len={} first_slot(original_len)={} total_slots_after_trunc={}",
        plaintext.len(),
        slots[0],
        slots.len()
    );
    Ok(slots)
}
