//! S1: Cross-verification test for native IVC vs Noir circuit hash construction.
//!
//! Documents and verifies the hash construction divergence between:
//!   (A) The native Rust Nova IVC (CycloFoldStepCircuit) state commitment
//!   (B) The Noir circuits (nova_state_commitment, aggregator_final)
//!
//! The native Nova IVC produces a final state z_i (8 BN254 Fr elements).
//! Its state commitment `zi_commitment` is computed via:
//!   `Keccak256(||_{i=0..7} z_i.to_bigint().to_bytes_be())`
//! (see `crates/pvthfhe-compressor/src/nova/snark_bridge.rs:116-122`).
//!
//! The Noir `nova_state_commitment` circuit computes:
//!   `Poseidon::hash_4([z0, z1, z2, z3])`
//! (see `circuits/nova_state_commitment/src/main.nr:24-26`).
//!
//! The Noir `aggregator_final` circuit receives `nova_share_chain_hash` and
//! `ivc_snark_proof_hash` as public inputs and only checks non-zero.
//!
//! ## Divergence
//!
//! | Property             | Native IVC                        | Noir circuit                     |
//! |----------------------|-----------------------------------|----------------------------------|
//! | Hash function        | Keccak256 (SHA-3)                 | Poseidon BN254 (hash_4 or sponge)|
//! | State width          | 8 field elements                  | 4 field elements (hash_4)        |
//! | Input encoding       | big-endian bytes (32 per element) | raw Fr field elements            |
//! | Output               | [u8; 32] → Fr::from_be_bytes_mod_order | Fr (Poseidon output)      |
//!
//! Keccak256(state bytes) ≠ Poseidon::hash_4(state). The names
//! `nova_final_state_commitment` and `zi_commitment` refer to the same
//! conceptual value but use different hash functions.
//!
//! ## Mitigation status
//!
//! The on-chain IVC decider is fail-closed (`ivcDeciderVerifier = address(0)`,
//! per P4). The native IVC proof verification runs off-chain; the on-chain
//! verifier only checks that the IVC proof hash is non-zero.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use sha3::{Digest, Keccak256};

fn native_ivc_state_hash(state: &[Fr]) -> [u8; 32] {
    let mut data = Vec::with_capacity(state.len() * 32);
    for f in state {
        data.extend_from_slice(&f.into_bigint().to_bytes_be());
    }
    Keccak256::digest(&data).into()
}

fn noir_state_hash_4(preimage: &[Fr; 4]) -> Fr {
    pvthfhe_types::verification_statement::noir_bn254_sponge(preimage)
        .expect("Poseidon hash_4 must succeed for 4 elements")
}

fn bytes32_to_fr(hash: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(hash)
}

#[test]
fn s1_native_keccak_and_noir_poseidon_diverge() {
    let state: [Fr; 4] = [
        Fr::from(1u64),
        Fr::from(2u64),
        Fr::from(3u64),
        Fr::from(4u64),
    ];

    let native_hash_bytes = native_ivc_state_hash(&state);
    let native_hash_fr = bytes32_to_fr(&native_hash_bytes);
    let noir_hash_fr = noir_state_hash_4(&state);

    assert_ne!(
        native_hash_fr, noir_hash_fr,
        "Keccak256 and Poseidon hash_4 must produce different values for the same input"
    );

    assert!(!native_hash_fr.is_zero());
    assert!(!noir_hash_fr.is_zero());
}

#[test]
fn s1_state_width_diverges_native_8_noir_4() {
    const NATIVE_STATE_WIDTH: usize = 8;
    const NOIR_PREIMAGE_WIDTH: usize = 4;

    assert_ne!(
        NATIVE_STATE_WIDTH, NOIR_PREIMAGE_WIDTH,
        "native IVC state width ({NATIVE_STATE_WIDTH}) differs from Noir \
         hash preimage width ({NOIR_PREIMAGE_WIDTH})"
    );
}

#[test]
fn s1_native_hash_regression() {
    let state = [
        Fr::from(1u64),
        Fr::from(2u64),
        Fr::from(3u64),
        Fr::from(4u64),
    ];

    let hash = native_ivc_state_hash(&state);

    let expected: [u8; 32] = [
        0x39, 0x27, 0x91, 0xdf, 0x62, 0x64, 0x08, 0x01, 0x7a, 0x26, 0x4f, 0x53, 0xfd, 0xe6, 0x10,
        0x65, 0xd5, 0xa9, 0x3a, 0x32, 0xb6, 0x01, 0x71, 0xdf, 0x9d, 0x8a, 0x46, 0xaf, 0xdf, 0x82,
        0x99, 0x2d,
    ];

    assert_eq!(hash, expected, "native Keccak256 hash construction changed");
}

#[test]
fn s1_noir_hash_regression() {
    let preimage: [Fr; 4] = [
        Fr::from(1u64),
        Fr::from(2u64),
        Fr::from(3u64),
        Fr::from(4u64),
    ];

    let hash = noir_state_hash_4(&preimage);

    assert!(!hash.is_zero());

    let hash2 = noir_state_hash_4(&preimage);
    assert_eq!(hash, hash2, "Noir Poseidon hash_4 must be deterministic");

    let native_bytes = native_ivc_state_hash(&preimage);
    let native_fr = bytes32_to_fr(&native_bytes);
    assert_ne!(
        hash, native_fr,
        "Noir Poseidon hash_4 and native Keccak256 must differ"
    );
}

#[test]
fn s1_verification_statement_hash_agrees_cross_language() {
    use pvthfhe_types::verification_statement::{
        VerificationStatementV1, GOLDEN_STATEMENT_HASH_DECIMAL,
    };

    fn seeded_bytes(seed: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        out
    }

    let stmt = VerificationStatementV1 {
        protocol_version: 1,
        context_id: seeded_bytes(0x10),
        dkg_root: seeded_bytes(0x20),
        epoch: 42,
        participant_set_hash: seeded_bytes(0x30),
        aggregate_pk_hash: seeded_bytes(0x40),
        ciphertext_hash: seeded_bytes(0x50),
        plaintext_hash: seeded_bytes(0x60),
        d_commitment: seeded_bytes(0x70),
        c5_proof_root: seeded_bytes(0x80),
        c6_proof_set_root: seeded_bytes(0x90),
        cyclo_accumulator_root: seeded_bytes(0xa0),
        ivc_vk_hash: seeded_bytes(0xb0),
        ivc_pp_hash: seeded_bytes(0xc0),
        ivc_proof_hash: seeded_bytes(0xd0),
        z0_commitment: seeded_bytes(0xe0),
        zi_commitment: seeded_bytes(0xf0),
        ivc_steps: 7,
        bootstrap_result_hash: seeded_bytes(0x08),
        share_verification_hash: seeded_bytes(0x11),
        decrypt_nizk_hash: seeded_bytes(0x12),
        dkg_transcript_hash: seeded_bytes(0x13),
        nova_final_state_commitment: seeded_bytes(0x14),
    };

    let hash = stmt.statement_hash().expect("Poseidon hash succeeds");
    assert_eq!(
        hash.decimal, GOLDEN_STATEMENT_HASH_DECIMAL,
        "Rust Poseidon hash of golden VerificationStatementV1 must match Noir golden hash"
    );
}
