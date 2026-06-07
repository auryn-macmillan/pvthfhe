//! Minimal Noir-compatible Poseidon sponge (x5_5) for deterministic hashing.
//!
//! Produces exactly the same hash as Noir's `poseidon::poseidon::bn254::sponge`.
//! Uses the exact Noir x5_5 round constants from the noir-lang poseidon crate.
//!
//! This module is a minimal subset of `pvthfhe-cli/src/noir_poseidon.rs`,
//! duplicated here to avoid a circular dependency (pvthfhe-cli depends on
//! pvthfhe-compressor, not vice versa).

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField, Zero};
use std::sync::OnceLock;

/// S-box exponent (alpha = 5).
const ALPHA: u64 = 5;

const NOIR_POSEIDON_CONSTS: &str = include_str!(
    "/home/dev/nargo/github.com/noir-lang/poseidon/v0.3.0/src/poseidon/bn254/consts.nr"
);

/// Parse a hex string into Fr (matches fr_hex in noir_poseidon.rs).
fn fr_hex(h: &str) -> Fr {
    let normalized;
    let h = if h.len() & 1 == 1 {
        normalized = format!("0{h}");
        normalized.as_str()
    } else {
        h
    };
    let bytes = hex::decode(h).expect("invalid hex in Poseidon constant");
    Fr::from_be_bytes_mod_order(&bytes)
}

/// Parse Noir Poseidon config from consts.nr (exact copy of pvthfhe-cli logic).
fn parse_noir_config(
    name: &str,
    t: usize,
    rf: usize,
    rp: usize,
    sparse_len: usize,
) -> (Vec<Fr>, Vec<Vec<Fr>>, Vec<Vec<Fr>>, Vec<Fr>) {
    let marker = format!("pub fn {name}() ->");
    let start = NOIR_POSEIDON_CONSTS
        .find(&marker)
        .unwrap_or_else(|| panic!("Noir Poseidon config {name} not found"));
    let after = &NOIR_POSEIDON_CONSTS[start..];
    let next = after[marker.len()..]
        .find("\n}\n\n// noir-fmt:ignore")
        .or_else(|| after[marker.len()..].find("\n}\n"))
        .expect("Noir Poseidon config terminator not found")
        + marker.len();
    let section = &after[..next];

    let mut values = Vec::new();
    let bytes = section.as_bytes();
    let mut i = 0;
    while i + 2 <= bytes.len() {
        if bytes[i] == b'0' && i + 1 < bytes.len() && bytes[i + 1] == b'x' {
            let hex_start = i + 2;
            let mut hex_end = hex_start;
            while hex_end < bytes.len() && bytes[hex_end].is_ascii_hexdigit() {
                hex_end += 1;
            }
            values.push(fr_hex(&section[hex_start..hex_end]));
            i = hex_end;
        } else {
            i += 1;
        }
    }

    let rc_len = t * rf + rp;
    let matrix_len = t * t;
    let expected = rc_len + matrix_len + matrix_len + sparse_len;
    assert_eq!(
        values.len(),
        expected,
        "unexpected constant count for Noir Poseidon config {name}"
    );

    let round_constants = values[..rc_len].to_vec();
    let mut offset = rc_len;
    let mds = values[offset..offset + matrix_len]
        .chunks(t)
        .map(|row| row.to_vec())
        .collect();
    offset += matrix_len;
    let presparse_mds = values[offset..offset + matrix_len]
        .chunks(t)
        .map(|row| row.to_vec())
        .collect();
    offset += matrix_len;
    let sparse_mds = values[offset..].to_vec();

    (round_constants, mds, presparse_mds, sparse_mds)
}

/// Lazy-loaded x5_5 config (t=5, rf=8, rp=60, sparse=540).
fn x5_5_config() -> &'static (Vec<Fr>, Vec<Vec<Fr>>, Vec<Vec<Fr>>, Vec<Fr>) {
    static CONFIG: OnceLock<(Vec<Fr>, Vec<Vec<Fr>>, Vec<Vec<Fr>>, Vec<Fr>)> = OnceLock::new();
    CONFIG.get_or_init(|| parse_noir_config("x5_5_config", 5, 8, 60, 540))
}

/// Apply alpha=S-box to all state elements.
fn sigma_slice(state: &mut [Fr]) {
    for s in state {
        *s = s.pow([ALPHA]);
    }
}

/// Apply MDS matrix to state.
fn apply_matrix_dynamic(matrix: &[Vec<Fr>], state: &mut [Fr]) {
    let t = state.len();
    let mut out = vec![Fr::zero(); t];
    for i in 0..t {
        for j in 0..t {
            out[i] += state[j] * matrix[j][i];
        }
    }
    state.copy_from_slice(&out);
}

/// Noir-compatible Poseidon permutation for x5_5.
fn permute_x5_5(state: &mut [Fr]) {
    let (round_constants, mds, presparse_mds, sparse_mds) = x5_5_config();
    let t = 5;
    let rf = 8;
    let rp = 60;

    // Initial ARK
    for (s, c) in state.iter_mut().zip(round_constants.iter().take(t)) {
        *s += c;
    }

    // First full rounds (rf/2 - 1)
    for rd in 0..(rf / 2 - 1) {
        sigma_slice(state);
        for i in 0..t {
            state[i] += round_constants[t * (rd + 1) + i];
        }
        apply_matrix_dynamic(mds, state);
    }

    // Last full round of first half: S-box + ARK + presparse_mds
    sigma_slice(state);
    for i in 0..t {
        state[i] += round_constants[t * (rf / 2) + i];
    }
    apply_matrix_dynamic(presparse_mds, state);

    // Partial rounds
    for rd in 0..rp {
        state[0] = state[0].pow([ALPHA]);
        state[0] += round_constants[(rf / 2 + 1) * t + rd];
        let sb = (t * 2 - 1) * rd;
        let mut new_state_0 = Fr::zero();
        for j in 0..t {
            new_state_0 += sparse_mds[sb + j] * state[j];
        }
        for k in 1..t {
            state[k] += state[0] * sparse_mds[sb + t + k - 1];
        }
        state[0] = new_state_0;
    }

    // Second full rounds (rf/2 - 1)
    for rd in 0..(rf / 2 - 1) {
        sigma_slice(state);
        let ri = (rf / 2 + 1) * t + rp + rd * t;
        for i in 0..t {
            state[i] += round_constants[ri + i];
        }
        apply_matrix_dynamic(mds, state);
    }

    // Final round: S-box + MDS (no ARK)
    sigma_slice(state);
    apply_matrix_dynamic(mds, state);
}

/// Noir-compatible Poseidon sponge using x5_5 (rate=4, capacity=1).
///
/// Matches Noir's `poseidon::poseidon::bn254::sponge(msg)` exactly.
pub fn sponge(inputs: &[Fr]) -> Fr {
    const RATE: usize = 4;
    const CAP: usize = 1;
    let mut state = [Fr::zero(); RATE + CAP];
    let mut i: usize = 0;
    for &input in inputs {
        state[CAP + i] += input;
        i += 1;
        if i == RATE {
            permute_x5_5(&mut state);
            i = 0;
        }
    }
    if i != 0 {
        permute_x5_5(&mut state);
    }
    state[CAP]
}

/// Hash arbitrary number of inputs through the sponge.
pub fn hash_n(inputs: &[Fr]) -> Fr {
    sponge(inputs)
}

/// Hash a variable-length sequence of elements using a chained sponge approach.
///
/// This processes elements as a chain: `sponge([elem0])`, then `sponge([state, elem1])`,
/// etc. This matches the Noir `hash_chain` function exactly, enabling cross-language
/// verification of variable-length inputs like proof byte chunks.
///
/// Returns `Fr::zero()` for empty input.
pub fn hash_chain(elements: &[Fr]) -> Fr {
    if elements.is_empty() {
        return Fr::zero();
    }
    let mut state = sponge(&[elements[0]]);
    for &elem in &elements[1..] {
        state = sponge(&[state, elem]);
    }
    state
}

/// Convert raw bytes into field elements (31-byte chunks padded to 32 bytes)
/// and hash them through the Noir sponge.
pub fn hash_bytes(input: &[u8]) -> Fr {
    let chunks: Vec<Fr> = input
        .chunks(31)
        .map(|chunk| {
            let mut padded = [0u8; 32];
            let start = 32 - chunk.len();
            padded[start..].copy_from_slice(chunk);
            Fr::from_be_bytes_mod_order(&padded)
        })
        .collect();
    sponge(&chunks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::PrimeField;

    // ── Cross-language hash agreement tests ──
    // These values match Noir's poseidon::bn254::sponge.

    #[test]
    fn test_cross_lang_sponge_empty() {
        assert!(sponge(&[]).is_zero());
    }

    #[test]
    fn test_cross_lang_sponge_1_2() {
        let h = sponge(&[Fr::from(1u64), Fr::from(2u64)]);
        assert_eq!(
            h,
            fr_hex("2dddd542213b9228162ff1b438c3709c057a9550103c9173c6204fb29b802c37")
        );
    }

    #[test]
    fn test_cross_lang_sponge_42() {
        let h = sponge(&[Fr::from(42u64)]);
        assert_eq!(
            h,
            fr_hex("13f3e672ad239ac1b07e621284c5c078a5319e9842df7222a180893243919052")
        );
    }

    #[test]
    fn test_cross_lang_sponge_1_to_9() {
        let inputs: Vec<Fr> = (1..=9).map(|i| Fr::from(i as u64)).collect();
        let h = sponge(&inputs);
        assert_eq!(
            h,
            fr_hex("078586eb4ca134c5c200d58088da25a5aa55e142e077b7e1a46c701bade73627")
        );
    }

    #[test]
    fn test_cross_lang_sponge_pair() {
        let h = sponge(&[Fr::from(0xdeadu64), Fr::from(0xbeefu64)]);
        assert_eq!(
            h,
            fr_hex("1ded065fd7e20cba7b17138b4e886ff4d2a4024dc06bc4021412ac749d870006")
        );
    }

    #[test]
    fn test_sponge_deterministic() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let c = Fr::from(3u64);
        let d = Fr::from(4u64);
        let h1 = sponge(&[a, b, c, d]);
        let h2 = sponge(&[a, b, c, d]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sponge_order_matters() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let c = Fr::from(3u64);
        let d = Fr::from(4u64);
        assert_ne!(sponge(&[a, b, c, d]), sponge(&[d, c, b, a]));
    }

    #[test]
    fn test_hash_bytes_deterministic() {
        let data = b"hello world test data";
        let h1 = hash_bytes(data);
        let h2 = hash_bytes(data);
        assert_eq!(h1, h2);
        assert!(!h1.is_zero());
    }

    #[test]
    fn test_hash_bytes_different_data() {
        let h1 = hash_bytes(b"aaaa");
        let h2 = hash_bytes(b"aaab");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_bytes_empty() {
        let h = hash_bytes(b"");
        assert!(h.is_zero()); // empty input → no elements → sponge([]) = 0
    }

    #[test]
    fn test_hash_bytes_31_byte_boundary() {
        let data = vec![0x42u8; 31];
        let h = hash_bytes(&data);
        assert!(!h.is_zero());
    }

    #[test]
    fn test_hash_bytes_32_bytes_two_chunks() {
        let data = vec![0x42u8; 32];
        let h = hash_bytes(&data);
        assert!(!h.is_zero());
    }

    #[test]
    fn test_hash_chain_deterministic() {
        let inputs: Vec<Fr> = (1..=5).map(|i| Fr::from(i as u64)).collect();
        let h1 = hash_chain(&inputs);
        let h2 = hash_chain(&inputs);
        assert_eq!(h1, h2);
        assert!(!h1.is_zero());
    }

    #[test]
    fn test_hash_chain_empty_returns_zero() {
        assert!(hash_chain(&[]).is_zero());
    }

    #[test]
    fn test_hash_chain_different_from_sponge() {
        let inputs: Vec<Fr> = (1..=5).map(|i| Fr::from(i as u64)).collect();
        let h_chain = hash_chain(&inputs);
        let h_sponge = sponge(&inputs);
        assert_ne!(
            h_chain, h_sponge,
            "hash_chain should differ from direct sponge"
        );
    }

    #[test]
    fn test_hash_chain_order_matters() {
        let a = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let b = [Fr::from(3u64), Fr::from(2u64), Fr::from(1u64)];
        assert_ne!(hash_chain(&a), hash_chain(&b));
    }
}
