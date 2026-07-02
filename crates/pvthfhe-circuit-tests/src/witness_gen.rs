//! Witness generator for the Noir `decrypt_share` circuit.
//!
//! ## DEPRECATED — Hash function mismatch (G.1, security review finding A.1)
//!
//! This module uses a custom `rolling_digest` for all hash computations.
//! The active pipeline (`full_pipeline.rs`) uses canonical Poseidon
//! `bind_8_with_domain_native` with domain tag 6. These are incompatible.
//!
//! The `decrypt_share` Noir circuit is currently deferred in the pipeline
//! (`pvthfhe_e2e.rs:207`). When activated:
//! 1. Replace all `rolling_digest_raw` calls with `bind_8_with_domain_native`
//! 2. Replace `rolling_digest_8_raw` calls with Poseidon sponge absorption
//! 3. Align domain tags with `protocol_constants/src/lib.nr`
//!
//! Until then, this module is kept for reference only and should not be used
//! as the basis for new circuit development.

use std::{fmt::Write as _, path::Path};

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField, Zero};
use light_poseidon::{Poseidon, PoseidonHasher};

/// Full RLWE ring degree used by the circuit.
pub const N: usize = 8192;
/// log2(N) for repeated squaring.
pub const LOG_N: usize = 13;
/// Error bound enforced by the circuit.
pub const B_E: u32 = 16;
/// Participant count used by the full-dimension aggregator witness.
pub const AGGREGATOR_N_PARTICIPANTS: u64 = 3;
/// Threshold used by the full-dimension aggregator witness.
pub const AGGREGATOR_THRESHOLD: u64 = 2;
/// Digest domain separator.
pub const DIGEST_DOMAIN: u64 = 987_654_321;

/// Ring dimension used by the aggregator_final circuit.
pub const AGGREGATOR_N: usize = 256;
/// Maximum number of shares used by the aggregator_final circuit.
pub const AGGREGATOR_MAX_SHARES: usize = 128;
/// Merkle tree depth used by the aggregator_final circuit (log2(128)=7).
pub const AGGREGATOR_DEPTH: usize = 7;

const DIGEST_BASE: u64 = 131;

/// Fully materialized witness in Noir `Prover.toml` string form.
#[derive(Debug, Clone)]
pub struct DecryptShareWitness {
    /// Public party identifier.
    pub party_id: String,
    /// Public rolling digest of `sk_i`.
    pub pk_i_hash: String,
    /// Public DKG root binding.
    pub dkg_root: String,
    /// Public ciphertext binding.
    pub ciphertext_hash: String,
    /// Public epoch.
    pub epoch: String,
    /// Public rolling digest of `c1`.
    pub c1_hash: String,
    /// Public rolling digest of `d_i`.
    pub d_i_hash: String,
    /// Public compact statement hash.
    pub compact_statement_hash: String,
    /// Private ternary secret key coefficients.
    pub sk_i: Vec<String>,
    /// Private bounded error coefficients.
    pub e_i: Vec<String>,
    /// Private ciphertext polynomial.
    pub c1: Vec<String>,
    /// Private decrypt-share polynomial hint.
    pub d_i: Vec<String>,
    /// Private quotient hint at the Fiat-Shamir challenge point.
    pub q: String,
}

/// Fully materialized witness in Noir `Prover.toml` string form.
#[derive(Debug, Clone)]
pub struct AggregatorFinalWitness {
    pub ciphertext_hash: String,
    pub aggregate_pk_hash: String,
    pub decrypt_nizk_hash: String,
    pub dkg_transcript_hash: String,
    pub dkg_root: String,
    pub session_id: String,
    pub epoch: String,
    pub participant_set_hash: String,
    pub n_participants: String,
    pub threshold: String,
    pub plaintext_commitment: String,
    pub ivc_snark_proof_hash: String,
    pub n_shares: String,
    pub share_commitment_root: String,
    pub committee_party_ids: Vec<String>,
    pub nova_final_plaintext: Vec<String>,
    pub nova_share_chain_hash: String,
    pub share_evals: Vec<String>,
    pub lagrange_coeffs: Vec<String>,
    pub pt_eval: String,
    pub combined_poly: Vec<String>,
    pub combined_merkle_path: Vec<String>,
    pub combined_leaf_index: String,
    pub aggregate_pk_leaf: String,
    pub merkle_path: Vec<String>,
    pub leaf_index: String,
    pub c2_pk0_eval: String,
    pub c2_pk1_eval: String,
    pub c2_ct0_eval: String,
    pub c2_ct1_eval: String,
    pub c2_u_eval: String,
    pub c2_e0_eval: String,
    pub c2_e1_eval: String,
    pub c2_m_eval: String,
    pub c2_recipient_pk_root: String,
    pub c2_delta: String,
    pub c2_pk0_coeffs: Vec<String>,
    pub c2_pk1_coeffs: Vec<String>,
    pub c2_ct0_coeffs: Vec<String>,
    pub c2_ct1_coeffs: Vec<String>,
    pub c2_u_coeffs: Vec<String>,
    pub c2_e0_coeffs: Vec<String>,
    pub c2_e1_coeffs: Vec<String>,
    pub c2_m_coeffs: Vec<String>,
    pub c2_pk0_commitment: String,
    pub c2_pk1_commitment: String,
    pub c2_pk_merkle_path: Vec<String>,
    pub c2_pk_leaf_index: String,
}

/// Fully materialized witness in Noir `Prover.toml` string form.
#[derive(Debug, Clone)]
pub struct NovaStateCommitmentWitness {
    /// Public commitment to the aggregate public key context.
    pub commit_pk: String,
    /// Public commitment to the input ciphertext context.
    pub commit_ct_in: String,
    /// Public commitment to the output ciphertext context.
    pub commit_ct_out: String,
    /// Public session identifier.
    pub session_id: String,
    /// Public Poseidon commitment to the Nova final-state preimage.
    pub nova_final_state_commitment: String,
    /// Public Poseidon commitment to the Cyclo aggregate preimage.
    pub cyclo_aggregate_commitment: String,
    /// Private Nova final-state preimage.
    pub nova_state_preimage: Vec<String>,
    /// Private Cyclo aggregate preimage.
    pub cyclo_aggregate_preimage: Vec<String>,
    /// IVC proof hash binding.
    pub ivc_proof_hash: String,
    /// IVC verifier key hash binding.
    pub ivc_vk_hash: String,
    /// IVC public params hash binding.
    pub ivc_pp_hash: String,
    /// IVC z0 commitment.
    pub z0_commitment: String,
    /// IVC zi commitment.
    pub zi_commitment: String,
    /// IVC step count.
    pub ivc_steps: String,
    /// Share verification hash binding.
    pub share_verification_hash: String,
    /// S6: IVC verification result (1 = passed, 0 = failed).
    pub ivc_verify_result: String,
    /// Bootstrap result hash binding.
    pub bootstrap_result_hash: String,
    /// P4-upgrade: Noir-compatible Poseidon hash of IVC proof bytes.
    pub noir_ivc_proof_hash: String,
    /// P4-upgrade: Noir-compatible Poseidon hash of z0 state.
    pub noir_z0_commitment: String,
    /// P4-upgrade: Noir-compatible Poseidon hash of zi state.
    pub noir_zi_commitment: String,
    /// S2: FHE Mul ops flag — 1 if at least one Mul was verified, 0 otherwise.
    pub has_fhe_mul_ops: String,
    /// P4-upgrade: Proof byte chunks as Field elements.
    pub ivc_proof_fields: Vec<String>,
    /// P4-upgrade: z0 state elements.
    pub z0_state_fields: Vec<String>,
    /// P4-upgrade: zi state elements.
    pub zi_state_fields: Vec<String>,
}

impl DecryptShareWitness {
    /// Serializes the witness into Noir `Prover.toml` syntax.
    pub fn to_toml(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(&mut output, "party_id = \"{}\"", self.party_id);
        let _ = writeln!(&mut output, "pk_i_hash = \"{}\"", self.pk_i_hash);
        let _ = writeln!(&mut output, "dkg_root = \"{}\"", self.dkg_root);
        let _ = writeln!(
            &mut output,
            "ciphertext_hash = \"{}\"",
            self.ciphertext_hash
        );
        let _ = writeln!(&mut output, "epoch = \"{}\"", self.epoch);
        let _ = writeln!(&mut output, "c1_hash = \"{}\"", self.c1_hash);
        let _ = writeln!(&mut output, "d_i_hash = \"{}\"", self.d_i_hash);
        let _ = writeln!(
            &mut output,
            "compact_statement_hash = \"{}\"",
            self.compact_statement_hash
        );
        let _ = writeln!(&mut output, "sk_i = [{}]", quoted_array(&self.sk_i));
        let _ = writeln!(&mut output, "e_i = [{}]", quoted_array(&self.e_i));
        let _ = writeln!(&mut output, "c1 = [{}]", quoted_array(&self.c1));
        let _ = writeln!(&mut output, "d_i = [{}]", quoted_array(&self.d_i));
        let _ = writeln!(&mut output, "q = \"{}\"", self.q);
        output
    }

    /// Writes the witness to a target file path.
    pub fn write_to_path(&self, path: &Path) -> std::io::Result<()> {
        std::fs::write(path, self.to_toml())
    }
}

impl AggregatorFinalWitness {
    pub fn to_toml(&self) -> String {
        let mut output = String::new();
        // Public inputs (12)
        let _ = writeln!(&mut output, "ciphertext_hash = \"{}\"", self.ciphertext_hash);
        let _ = writeln!(&mut output, "aggregate_pk_hash = \"{}\"", self.aggregate_pk_hash);
        let _ = writeln!(&mut output, "decrypt_nizk_hash = \"{}\"", self.decrypt_nizk_hash);
        let _ = writeln!(&mut output, "dkg_transcript_hash = \"{}\"", self.dkg_transcript_hash);
        let _ = writeln!(&mut output, "dkg_root = \"{}\"", self.dkg_root);
        let _ = writeln!(&mut output, "session_id = \"{}\"", self.session_id);
        let _ = writeln!(&mut output, "epoch = \"{}\"", self.epoch);
        let _ = writeln!(&mut output, "participant_set_hash = \"{}\"", self.participant_set_hash);
        let _ = writeln!(&mut output, "n_participants = \"{}\"", self.n_participants);
        let _ = writeln!(&mut output, "threshold = \"{}\"", self.threshold);
        let _ = writeln!(&mut output, "plaintext_commitment = \"{}\"", self.plaintext_commitment);
        let _ = writeln!(&mut output, "ivc_snark_proof_hash = \"{}\"", self.ivc_snark_proof_hash);
        // C7 public inputs (3)
        let _ = writeln!(&mut output, "n_shares = \"{}\"", self.n_shares);
        let _ = writeln!(&mut output, "share_commitment_root = \"{}\"", self.share_commitment_root);
        let _ = writeln!(&mut output, "committee_party_ids = [{}]", bare_array(&self.committee_party_ids));
        // Nova final state (2)
        let _ = writeln!(&mut output, "nova_final_plaintext = [{}]", bare_array(&self.nova_final_plaintext));
        let _ = writeln!(&mut output, "nova_share_chain_hash = \"{}\"", self.nova_share_chain_hash);
        // C7 witnesses (7)
        let _ = writeln!(&mut output, "share_evals = [{}]", bare_array(&self.share_evals));
        let _ = writeln!(&mut output, "lagrange_coeffs = [{}]", bare_array(&self.lagrange_coeffs));
        let _ = writeln!(&mut output, "pt_eval = \"{}\"", self.pt_eval);
        let _ = writeln!(&mut output, "combined_poly = [{}]", bare_array(&self.combined_poly));
        let _ = writeln!(&mut output, "combined_merkle_path = [{}]", bare_array(&self.combined_merkle_path));
        let _ = writeln!(&mut output, "combined_leaf_index = \"{}\"", self.combined_leaf_index);
        // G4 witnesses (3)
        let _ = writeln!(&mut output, "aggregate_pk_leaf = \"{}\"", self.aggregate_pk_leaf);
        let _ = writeln!(&mut output, "merkle_path = [{}]", bare_array(&self.merkle_path));
        let _ = writeln!(&mut output, "leaf_index = \"{}\"", self.leaf_index);
        // C2 public inputs (10)
        let _ = writeln!(&mut output, "c2_pk0_eval = \"{}\"", self.c2_pk0_eval);
        let _ = writeln!(&mut output, "c2_pk1_eval = \"{}\"", self.c2_pk1_eval);
        let _ = writeln!(&mut output, "c2_ct0_eval = \"{}\"", self.c2_ct0_eval);
        let _ = writeln!(&mut output, "c2_ct1_eval = \"{}\"", self.c2_ct1_eval);
        let _ = writeln!(&mut output, "c2_u_eval = \"{}\"", self.c2_u_eval);
        let _ = writeln!(&mut output, "c2_e0_eval = \"{}\"", self.c2_e0_eval);
        let _ = writeln!(&mut output, "c2_e1_eval = \"{}\"", self.c2_e1_eval);
        let _ = writeln!(&mut output, "c2_m_eval = \"{}\"", self.c2_m_eval);
        let _ = writeln!(&mut output, "c2_recipient_pk_root = \"{}\"", self.c2_recipient_pk_root);
        let _ = writeln!(&mut output, "c2_delta = \"{}\"", self.c2_delta);
        // C2 witnesses (12): 8 coefficient arrays + 2 commitments + merkle path + leaf_index
        let _ = writeln!(&mut output, "c2_pk0_coeffs = [{}]", bare_array(&self.c2_pk0_coeffs));
        let _ = writeln!(&mut output, "c2_pk1_coeffs = [{}]", bare_array(&self.c2_pk1_coeffs));
        let _ = writeln!(&mut output, "c2_ct0_coeffs = [{}]", bare_array(&self.c2_ct0_coeffs));
        let _ = writeln!(&mut output, "c2_ct1_coeffs = [{}]", bare_array(&self.c2_ct1_coeffs));
        let _ = writeln!(&mut output, "c2_u_coeffs = [{}]", bare_array(&self.c2_u_coeffs));
        let _ = writeln!(&mut output, "c2_e0_coeffs = [{}]", bare_array(&self.c2_e0_coeffs));
        let _ = writeln!(&mut output, "c2_e1_coeffs = [{}]", bare_array(&self.c2_e1_coeffs));
        let _ = writeln!(&mut output, "c2_m_coeffs = [{}]", bare_array(&self.c2_m_coeffs));
        let _ = writeln!(&mut output, "c2_pk0_commitment = \"{}\"", self.c2_pk0_commitment);
        let _ = writeln!(&mut output, "c2_pk1_commitment = \"{}\"", self.c2_pk1_commitment);
        let _ = writeln!(&mut output, "c2_pk_merkle_path = [{}]", bare_array(&self.c2_pk_merkle_path));
        let _ = writeln!(&mut output, "c2_pk_leaf_index = \"{}\"", self.c2_pk_leaf_index);
        output
    }

    /// Writes the witness to a target file path.
    pub fn write_to_path(&self, path: &Path) -> std::io::Result<()> {
        std::fs::write(path, self.to_toml())
    }
}

impl NovaStateCommitmentWitness {
    /// Serializes the witness into Noir `Prover.toml` syntax.
    pub fn to_toml(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(&mut output, "commit_pk = \"{}\"", self.commit_pk);
        let _ = writeln!(&mut output, "commit_ct_in = \"{}\"", self.commit_ct_in);
        let _ = writeln!(&mut output, "commit_ct_out = \"{}\"", self.commit_ct_out);
        let _ = writeln!(&mut output, "session_id = \"{}\"", self.session_id);
        let _ = writeln!(
            &mut output,
            "nova_final_state_commitment = \"{}\"",
            self.nova_final_state_commitment
        );
        let _ = writeln!(
            &mut output,
            "cyclo_aggregate_commitment = \"{}\"",
            self.cyclo_aggregate_commitment
        );
        let _ = writeln!(
            &mut output,
            "nova_state_preimage = [{}]",
            quoted_array(&self.nova_state_preimage)
        );
        let _ = writeln!(&mut output, "ivc_proof_hash = \"{}\"", self.ivc_proof_hash);
        let _ = writeln!(&mut output, "ivc_vk_hash = \"{}\"", self.ivc_vk_hash);
        let _ = writeln!(&mut output, "ivc_pp_hash = \"{}\"", self.ivc_pp_hash);
        let _ = writeln!(&mut output, "z0_commitment = \"{}\"", self.z0_commitment);
        let _ = writeln!(&mut output, "zi_commitment = \"{}\"", self.zi_commitment);
        let _ = writeln!(&mut output, "ivc_steps = \"{}\"", self.ivc_steps);
        let _ = writeln!(
            &mut output,
            "share_verification_hash = \"{}\"",
            self.share_verification_hash
        );
        let _ = writeln!(
            &mut output,
            "ivc_verify_result = \"{}\"",
            self.ivc_verify_result
        );
        let _ = writeln!(
            &mut output,
            "bootstrap_result_hash = \"{}\"",
            self.bootstrap_result_hash
        );
        // P4-upgrade: Noir-compatible Poseidon hashes
        let _ = writeln!(
            &mut output,
            "noir_ivc_proof_hash = \"{}\"",
            self.noir_ivc_proof_hash
        );
        let _ = writeln!(
            &mut output,
            "noir_z0_commitment = \"{}\"",
            self.noir_z0_commitment
        );
        let _ = writeln!(
            &mut output,
            "noir_zi_commitment = \"{}\"",
            self.noir_zi_commitment
        );
        // S2: FHE Mul ops flag
        let _ = writeln!(
            &mut output,
            "has_fhe_mul_ops = \"{}\"",
            self.has_fhe_mul_ops
        );
        // P4-upgrade: Private witness arrays
        let _ = writeln!(
            &mut output,
            "ivc_proof_fields = [{}]",
            quoted_array(&self.ivc_proof_fields)
        );
        let _ = writeln!(
            &mut output,
            "z0_state_fields = [{}]",
            quoted_array(&self.z0_state_fields)
        );
        let _ = writeln!(
            &mut output,
            "zi_state_fields = [{}]",
            quoted_array(&self.zi_state_fields)
        );
        let _ = writeln!(
            &mut output,
            "cyclo_aggregate_preimage = [{}]",
            quoted_array(&self.cyclo_aggregate_preimage)
        );
        output
    }

    /// Writes the witness to a target file path.
    pub fn write_to_path(&self, path: &Path) -> std::io::Result<()> {
        std::fs::write(path, self.to_toml())
    }
}

/// Generates a valid witness for the full-dimension `decrypt_share` circuit.
pub fn generate_decrypt_share_witness() -> DecryptShareWitness {
    let party_id = Fr::from(1u64);
    let epoch = Fr::from(1u64);

    let mut sk_i_raw = vec![Fr::from(0u64); N];
    sk_i_raw[0] = Fr::from(1u64);
    sk_i_raw[1] = -Fr::from(1u64);

    let mut e_i_raw = vec![Fr::from(0u64); N];
    e_i_raw[0] = Fr::from(3u64);

    let mut c1_raw = vec![Fr::from(0u64); N];
    c1_raw[0] = Fr::from(42u64);
    c1_raw[1] = Fr::from(100u64);

    let pk_i_hash = rolling_digest_raw(&sk_i_raw);
    let c1_hash = rolling_digest_raw(&c1_raw);
    let dkg_root = dkg_binding_raw(party_id, pk_i_hash, epoch, c1_hash);
    let ciphertext_hash = ciphertext_binding_raw(party_id, pk_i_hash, dkg_root, epoch, c1_hash);
    let d_i_raw = add_polys(&negacyclic_convolution(&c1_raw, &sk_i_raw), &e_i_raw);
    let d_i_hash = rolling_digest_raw(&d_i_raw);
    let compact_statement_hash = statement_hash_raw(
        party_id,
        pk_i_hash,
        dkg_root,
        ciphertext_hash,
        epoch,
        c1_hash,
        d_i_hash,
    );
    let challenge_inputs = [
        party_id,
        pk_i_hash,
        dkg_root,
        ciphertext_hash,
        epoch,
        c1_hash,
        d_i_hash,
        compact_statement_hash,
    ];
    let r = rolling_digest_8_raw(&challenge_inputs);
    let r_to_n = r_pow_n(r);
    let lhs = eval_poly_raw(&d_i_raw, r);
    let rhs = eval_poly_raw(&c1_raw, r) * eval_poly_raw(&sk_i_raw, r) + eval_poly_raw(&e_i_raw, r);
    let denominator = r_to_n + Fr::from(1u64);
    let q = (rhs - lhs)
        * match denominator.inverse() {
            Some(inv) => inv,
            None => Fr::from(0u64),
        };

    DecryptShareWitness {
        party_id: field_to_decimal(party_id),
        pk_i_hash: field_to_decimal(pk_i_hash),
        dkg_root: field_to_decimal(dkg_root),
        ciphertext_hash: field_to_decimal(ciphertext_hash),
        epoch: field_to_decimal(epoch),
        c1_hash: field_to_decimal(c1_hash),
        d_i_hash: field_to_decimal(d_i_hash),
        compact_statement_hash: field_to_decimal(compact_statement_hash),
        sk_i: sk_i_raw.into_iter().map(field_to_decimal).collect(),
        e_i: e_i_raw.into_iter().map(field_to_decimal).collect(),
        c1: c1_raw.into_iter().map(field_to_decimal).collect(),
        d_i: d_i_raw.into_iter().map(field_to_decimal).collect(),
        q: field_to_decimal(q),
    }
}

/// Generates a valid witness for the full-dimension `aggregator_final` circuit.
///
/// Uses n_shares=1 (single-party) so λ₀=1 trivially passes the in-circuit
/// Lagrange coefficient verification without needing to compute the correct λ
/// for a full committee in native Rust.
///
/// All Poseidon hash values are computed using the canonical BN254 Poseidon
/// sponge (`poseidon_sponge_hash_native`) which matches Noir's in-circuit
/// `poseidon::poseidon::bn254::sponge`.
pub fn generate_aggregator_final_witness() -> AggregatorFinalWitness {
    use pvthfhe_compressor::witness::poseidon_sponge_hash_native;

    let zero = Fr::from(0u64);

    // ── Public input hashes ──

    // plaintext_commitment = vector_hash([0;256], 1) = poseidon([1, 0, 0, ..., 0])
    let mut pt_vec_hash_input = vec![Fr::from(1u64)];
    pt_vec_hash_input.extend(vec![zero; AGGREGATOR_N]);
    let plaintext_commitment = poseidon_sponge_hash_native(&pt_vec_hash_input);

    // ciphertext_hash must differ from plaintext_commitment (line 375)
    let ciphertext_hash = poseidon_sponge_hash_native(&[Fr::from(999u64)]);

    // aggregate_pk_leaf = 42, hash = poseidon([42])
    let aggregate_pk_leaf = Fr::from(42u64);
    let aggregate_pk_hash = poseidon_sponge_hash_native(&[aggregate_pk_leaf]);

    // dkg_root = compute_merkle_root(42, [0;7], 0) = repeated hash_pair(current, 0)
    let mut dkg_root = aggregate_pk_leaf;
    for _ in 0..AGGREGATOR_DEPTH {
        dkg_root = poseidon_sponge_hash_native(&[dkg_root, zero]);
    }

    // share_commitment_root = Merkle root of 128 leaf commitments.
    // For the neutral fixture all share polynomials are zero.
    let zero_poly_commitment = {
        let mut input = vec![Fr::from(1u64)];
        input.extend(vec![zero; AGGREGATOR_N]);
        poseidon_sponge_hash_native(&input)
    };
    let mut share_commitment_root = zero_poly_commitment;
    for _ in 0..7 {
        share_commitment_root = poseidon_sponge_hash_native(&[share_commitment_root, zero_poly_commitment]);
    }

    // Remaining distinct non-zero public input hashes
    let decrypt_nizk_hash = poseidon_sponge_hash_native(&[Fr::from(101u64)]);
    let dkg_transcript_hash = poseidon_sponge_hash_native(&[Fr::from(102u64)]);
    let session_id = Fr::from(1u64);
    let epoch = Fr::from(1u64);
    let participant_set_hash = poseidon_sponge_hash_native(&[Fr::from(300u64)]);
    let n_participants = Fr::from(10u64);
    let threshold = Fr::from(4u64);
    let ivc_snark_proof_hash = poseidon_sponge_hash_native(&[Fr::from(103u64)]);

    // C7 public inputs
    let n_shares = Fr::from(1u64);

    // Nova state
    let nova_final_plaintext_raw = vec![zero; AGGREGATOR_N];
    let nova_share_chain_hash = poseidon_sponge_hash_native(&[Fr::from(200u64)]);

    // C7 witnesses — all zero except lagrange_coeffs[0]=1 for n_shares=1
    let share_evals_raw = vec![zero; AGGREGATOR_MAX_SHARES];
    let pt_eval = zero;
    let combined_poly_raw = vec![zero; AGGREGATOR_N];
    let combined_merkle_path_raw = vec![zero; AGGREGATOR_DEPTH];
    let combined_leaf_index = zero;

    // committee_party_ids: [1, 0, ..., 0] for n_shares=1
    let mut committee_party_ids_raw = vec![zero; AGGREGATOR_MAX_SHARES];
    committee_party_ids_raw[0] = Fr::from(1u64);

    // lagrange_coeffs: [1, 0, ..., 0] for n_shares=1 (single-party λ₀=1)
    let mut lagrange_coeffs_raw = vec![zero; AGGREGATOR_MAX_SHARES];
    lagrange_coeffs_raw[0] = Fr::from(1u64);

    // G4 witnesses (from g4_neutral_fixture: leaf=42, path=zeros, index=0)
    let aggregate_pk_leaf = Fr::from(42u64);
    let merkle_path_raw = vec![zero; AGGREGATOR_DEPTH];
    let leaf_index = zero;

    // C2 public inputs — neutral (all zeros)
    let c2_zero_eval = zero;
    let c2_recipient_pk_root = Fr::from(11u64);
    let c2_delta = zero;

    // C2 witnesses — neutral coefficient arrays + distinct commitments
    let c2_zero_coeffs: Vec<Fr> = vec![zero; AGGREGATOR_N];
    let c2_pk0_commitment = Fr::from(12u64);
    let c2_pk1_commitment = Fr::from(13u64);
    let c2_pk_merkle_path_raw = vec![zero; AGGREGATOR_DEPTH];
    let c2_pk_leaf_index = zero;

    AggregatorFinalWitness {
        ciphertext_hash: field_to_decimal(ciphertext_hash),
        aggregate_pk_hash: field_to_decimal(aggregate_pk_hash),
        decrypt_nizk_hash: field_to_decimal(decrypt_nizk_hash),
        dkg_transcript_hash: field_to_decimal(dkg_transcript_hash),
        dkg_root: field_to_decimal(dkg_root),
        session_id: field_to_decimal(session_id),
        epoch: field_to_decimal(epoch),
        participant_set_hash: field_to_decimal(participant_set_hash),
        n_participants: field_to_decimal(n_participants),
        threshold: field_to_decimal(threshold),
        plaintext_commitment: field_to_decimal(plaintext_commitment),
        ivc_snark_proof_hash: field_to_decimal(ivc_snark_proof_hash),
        n_shares: field_to_decimal(n_shares),
        share_commitment_root: field_to_decimal(share_commitment_root),
        committee_party_ids: committee_party_ids_raw.into_iter().map(field_to_decimal).collect(),
        nova_final_plaintext: nova_final_plaintext_raw.into_iter().map(field_to_decimal).collect(),
        nova_share_chain_hash: field_to_decimal(nova_share_chain_hash),
        share_evals: share_evals_raw.into_iter().map(field_to_decimal).collect(),
        lagrange_coeffs: lagrange_coeffs_raw.into_iter().map(field_to_decimal).collect(),
        pt_eval: field_to_decimal(pt_eval),
        combined_poly: combined_poly_raw.into_iter().map(field_to_decimal).collect(),
        combined_merkle_path: combined_merkle_path_raw.into_iter().map(field_to_decimal).collect(),
        combined_leaf_index: field_to_decimal(combined_leaf_index),
        aggregate_pk_leaf: field_to_decimal(aggregate_pk_leaf),
        merkle_path: merkle_path_raw.into_iter().map(field_to_decimal).collect(),
        leaf_index: field_to_decimal(leaf_index),
        c2_pk0_eval: field_to_decimal(c2_zero_eval),
        c2_pk1_eval: field_to_decimal(c2_zero_eval),
        c2_ct0_eval: field_to_decimal(c2_zero_eval),
        c2_ct1_eval: field_to_decimal(c2_zero_eval),
        c2_u_eval: field_to_decimal(c2_zero_eval),
        c2_e0_eval: field_to_decimal(c2_zero_eval),
        c2_e1_eval: field_to_decimal(c2_zero_eval),
        c2_m_eval: field_to_decimal(c2_zero_eval),
        c2_recipient_pk_root: field_to_decimal(c2_recipient_pk_root),
        c2_delta: field_to_decimal(c2_delta),
        c2_pk0_coeffs: c2_zero_coeffs.clone().into_iter().map(field_to_decimal).collect(),
        c2_pk1_coeffs: c2_zero_coeffs.clone().into_iter().map(field_to_decimal).collect(),
        c2_ct0_coeffs: c2_zero_coeffs.clone().into_iter().map(field_to_decimal).collect(),
        c2_ct1_coeffs: c2_zero_coeffs.clone().into_iter().map(field_to_decimal).collect(),
        c2_u_coeffs: c2_zero_coeffs.clone().into_iter().map(field_to_decimal).collect(),
        c2_e0_coeffs: c2_zero_coeffs.clone().into_iter().map(field_to_decimal).collect(),
        c2_e1_coeffs: c2_zero_coeffs.clone().into_iter().map(field_to_decimal).collect(),
        c2_m_coeffs: c2_zero_coeffs.into_iter().map(field_to_decimal).collect(),
        c2_pk0_commitment: field_to_decimal(c2_pk0_commitment),
        c2_pk1_commitment: field_to_decimal(c2_pk1_commitment),
        c2_pk_merkle_path: c2_pk_merkle_path_raw.into_iter().map(field_to_decimal).collect(),
        c2_pk_leaf_index: field_to_decimal(c2_pk_leaf_index),
    }
}

/// Generates a valid witness for the `nova_state_commitment` circuit.
pub fn generate_nova_state_commitment_witness() -> NovaStateCommitmentWitness {
    let nova_state_preimage_raw = [
        Fr::from(10u64),
        Fr::from(20u64),
        Fr::from(30u64),
        Fr::from(40u64),
    ];
    let cyclo_aggregate_preimage_raw = [
        Fr::from(50u64),
        Fr::from(60u64),
        Fr::from(70u64),
        Fr::from(80u64),
    ];

    // P4-upgrade: compute Noir-compatible Poseidon hashes from witness data.
    // Uses pvthfhe_compressor::nova::noir_sponge::sponge which matches Noir's
    // poseidon::poseidon::bn254::sponge exactly.
    // PROOF_MAX_CHUNKS must match the Noir circuit global.
    const PROOF_MAX: usize = 64;
    let z0_state: [Fr; 8] = [
        Fr::from(10u64),
        Fr::from(20u64),
        Fr::from(30u64),
        Fr::from(40u64),
        Fr::from(50u64),
        Fr::from(60u64),
        Fr::from(70u64),
        Fr::from(80u64),
    ];
    let zi_state: [Fr; 8] = [
        Fr::from(11u64),
        Fr::from(22u64),
        Fr::from(33u64),
        Fr::from(44u64),
        Fr::from(55u64),
        Fr::from(66u64),
        Fr::from(77u64),
        Fr::from(88u64),
    ];

    let proof_chunks_raw: [Fr; PROOF_MAX] = {
        let mut arr = [Fr::zero(); PROOF_MAX];
        for i in 0..3 {
            arr[i] = Fr::from((i + 1) as u64); // [1, 2, 3, 0, 0, ...]
        }
        arr
    };

    NovaStateCommitmentWitness {
        commit_pk: field_to_decimal(Fr::from(1u64)),
        commit_ct_in: field_to_decimal(Fr::from(2u64)),
        commit_ct_out: field_to_decimal(Fr::from(3u64)),
        session_id: field_to_decimal(Fr::from(1u64)),
        nova_final_state_commitment: field_to_decimal(poseidon_hash_4(&nova_state_preimage_raw)),
        cyclo_aggregate_commitment: field_to_decimal(poseidon_hash_4(
            &cyclo_aggregate_preimage_raw,
        )),
        nova_state_preimage: nova_state_preimage_raw
            .into_iter()
            .map(field_to_decimal)
            .collect(),
        cyclo_aggregate_preimage: cyclo_aggregate_preimage_raw
            .into_iter()
            .map(field_to_decimal)
            .collect(),
        ivc_proof_hash: field_to_decimal(Fr::from(100u64)),
        ivc_vk_hash: field_to_decimal(Fr::from(200u64)),
        ivc_pp_hash: field_to_decimal(Fr::from(300u64)),
        z0_commitment: field_to_decimal(Fr::from(400u64)),
        zi_commitment: field_to_decimal(Fr::from(500u64)),
        ivc_steps: field_to_decimal(Fr::from(7u64)),
        share_verification_hash: field_to_decimal(Fr::from(999u64)),
        ivc_verify_result: field_to_decimal(Fr::from(1u64)),
        bootstrap_result_hash: field_to_decimal(Fr::from(888u64)),
        noir_ivc_proof_hash: field_to_decimal(
            pvthfhe_compressor::witness::poseidon_sponge_hash_native(&proof_chunks_raw),
        ),
        noir_z0_commitment: field_to_decimal(
            pvthfhe_compressor::witness::poseidon_sponge_hash_native(&z0_state),
        ),
        noir_zi_commitment: field_to_decimal(
            pvthfhe_compressor::witness::poseidon_sponge_hash_native(&zi_state),
        ),
        has_fhe_mul_ops: field_to_decimal(Fr::from(1u64)),
        ivc_proof_fields: proof_chunks_raw
            .iter()
            .map(|&f| field_to_decimal(f))
            .collect(),
        z0_state_fields: z0_state.iter().map(|&f| field_to_decimal(f)).collect(),
        zi_state_fields: zi_state.iter().map(|&f| field_to_decimal(f)).collect(),
    }
}

/// Computes the circuit rolling digest over decimal-encoded field values.
pub fn rolling_digest(values: &[String]) -> String {
    let raw_values: Vec<Fr> = values.iter().map(|value| decimal_to_field(value)).collect();
    field_to_decimal(rolling_digest_raw(&raw_values))
}

/// Computes the circuit eight-element rolling digest over decimal-encoded field values.
pub fn rolling_digest_8(values: &[String; 8]) -> String {
    let raw_values = values.each_ref().map(|value| decimal_to_field(value));
    field_to_decimal(rolling_digest_8_raw(&raw_values))
}

// DEPRECATED: use Poseidon bind_8_with_domain_native instead (see G.1)
fn rolling_digest_raw(values: &[Fr]) -> Fr {
    let mut acc = Fr::from(DIGEST_DOMAIN);
    let mut factor = Fr::from(1u64);
    let base = Fr::from(DIGEST_BASE);

    for value in values {
        acc += *value * factor;
        factor *= base;
    }

    acc
}

// DEPRECATED: use Poseidon bind_8_with_domain_native instead (see G.1)
fn rolling_digest_8_raw(values: &[Fr; 8]) -> Fr {
    rolling_digest_raw(values)
}

#[allow(clippy::as_conversions)]
fn dkg_binding_raw(party_id: Fr, pk_i_hash: Fr, epoch: Fr, c1_hash: Fr) -> Fr {
    rolling_digest_8_raw(&[
        party_id,
        pk_i_hash,
        epoch,
        c1_hash,
        Fr::from(N as u64),
        Fr::from(B_E as u64),
        Fr::from(11u64),
        Fr::from(19u64),
    ])
}

fn ciphertext_binding_raw(party_id: Fr, pk_i_hash: Fr, dkg_root: Fr, epoch: Fr, c1_hash: Fr) -> Fr {
    rolling_digest_8_raw(&[
        party_id,
        pk_i_hash,
        dkg_root,
        epoch,
        c1_hash,
        Fr::from(1u64),
        Fr::from(2u64),
        Fr::from(3u64),
    ])
}

#[allow(clippy::as_conversions)]
fn statement_hash_raw(
    party_id: Fr,
    pk_i_hash: Fr,
    dkg_root: Fr,
    ciphertext_hash: Fr,
    epoch: Fr,
    c1_hash: Fr,
    d_i_hash: Fr,
) -> Fr {
    rolling_digest_8_raw(&[
        party_id,
        pk_i_hash,
        dkg_root,
        ciphertext_hash,
        epoch,
        c1_hash,
        d_i_hash,
        Fr::from((N as u64) + (B_E as u64)),
    ])
}

fn negacyclic_convolution(left: &[Fr], right: &[Fr]) -> Vec<Fr> {
    let mut result = vec![Fr::from(0u64); N];

    for (i, &left_value) in left.iter().enumerate() {
        if left_value == Fr::from(0u64) {
            continue;
        }

        for (j, &right_value) in right.iter().enumerate() {
            if right_value == Fr::from(0u64) {
                continue;
            }

            let target = i + j;
            let coeff = left_value * right_value;
            if target < N {
                result[target] += coeff;
            } else {
                result[target - N] -= coeff;
            }
        }
    }

    result
}

fn add_polys(left: &[Fr], right: &[Fr]) -> Vec<Fr> {
    left.iter()
        .zip(right)
        .map(|(lhs, rhs)| *lhs + *rhs)
        .collect()
}

fn eval_poly_raw(coeffs: &[Fr], r: Fr) -> Fr {
    let mut result = Fr::from(0u64);

    for coeff in coeffs.iter().rev() {
        result *= r;
        result += coeff;
    }

    result
}

fn r_pow_n(r: Fr) -> Fr {
    let mut result = r;
    for _ in 0..LOG_N {
        result = result.square();
    }
    result
}

fn decimal_to_field(value: &str) -> Fr {
    match value.parse::<Fr>() {
        Ok(v) => v,
        Err(_) => Fr::from(0u64),
    }
}

fn poseidon_hash_4(values: &[Fr; 4]) -> Fr {
    let mut hasher = match Poseidon::<Fr>::new_circom(4) {
        Ok(h) => h,
        Err(_) => return Fr::from(0u64),
    };
    match hasher.hash(values) {
        Ok(h) => h,
        Err(_) => Fr::from(0u64),
    }
}

fn field_to_decimal(value: Fr) -> String {
    value.into_bigint().to_string()
}

fn quoted_array(values: &[String]) -> String {
    values
        .iter()
        .map(|value| format!("\"{value}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

fn bare_array(values: &[String]) -> String {
    values
        .iter()
        .map(|value| value.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}
