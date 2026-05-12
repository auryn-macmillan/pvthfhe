//! Witness generation for the full-dimension `decrypt_share` circuit.

use std::{fmt::Write as _, path::Path};

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};
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
    /// Public ciphertext binding hash.
    pub ciphertext_hash: String,
    /// Public rolling digest of the reconstructed plaintext polynomial.
    pub plaintext_hash: String,
    /// Public aggregate public-key binding hash.
    pub aggregate_pk_hash: String,
    /// Public DKG root binding reused from the decrypt-share witness.
    pub dkg_root: String,
    /// Public epoch.
    pub epoch: String,
    /// Public participant-set hash.
    pub participant_set_hash: String,
    /// Public commitment binding the decrypt-share hashes and threshold metadata.
    pub d_commitment: String,
    /// Private decrypt share from party 1.
    pub d1: Vec<String>,
    /// Private decrypt share from party 2.
    pub d2: Vec<String>,
    /// Private decrypt share from party 3.
    pub d3: Vec<String>,
    /// Private reconstructed plaintext polynomial hint.
    pub plaintext: Vec<String>,
    /// Private Schwartz-Zippel quotient hint.
    pub q: String,
}

/// Fully materialized witness in Noir `Prover.toml` string form.
#[derive(Debug, Clone)]
pub struct SonobeStateCommitmentWitness {
    /// Public commitment to the aggregate public key context.
    pub commit_pk: String,
    /// Public commitment to the input ciphertext context.
    pub commit_ct_in: String,
    /// Public commitment to the output ciphertext context.
    pub commit_ct_out: String,
    /// Public session identifier.
    pub session_id: String,
    /// Public Poseidon commitment to the Sonobe final-state preimage.
    pub sonobe_final_state_commitment: String,
    /// Public Poseidon commitment to the Cyclo aggregate preimage.
    pub cyclo_aggregate_commitment: String,
    /// Private Sonobe final-state preimage.
    pub sonobe_state_preimage: Vec<String>,
    /// Private Cyclo aggregate preimage.
    pub cyclo_aggregate_preimage: Vec<String>,
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
    /// Serializes the witness into Noir `Prover.toml` syntax.
    pub fn to_toml(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(
            &mut output,
            "ciphertext_hash = \"{}\"",
            self.ciphertext_hash
        );
        let _ = writeln!(&mut output, "plaintext_hash = \"{}\"", self.plaintext_hash);
        let _ = writeln!(
            &mut output,
            "aggregate_pk_hash = \"{}\"",
            self.aggregate_pk_hash
        );
        let _ = writeln!(&mut output, "dkg_root = \"{}\"", self.dkg_root);
        let _ = writeln!(&mut output, "epoch = \"{}\"", self.epoch);
        let _ = writeln!(
            &mut output,
            "participant_set_hash = \"{}\"",
            self.participant_set_hash
        );
        let _ = writeln!(&mut output, "d_commitment = \"{}\"", self.d_commitment);
        let _ = writeln!(&mut output, "d1 = [{}]", quoted_array(&self.d1));
        let _ = writeln!(&mut output, "d2 = [{}]", quoted_array(&self.d2));
        let _ = writeln!(&mut output, "d3 = [{}]", quoted_array(&self.d3));
        let _ = writeln!(
            &mut output,
            "plaintext = [{}]",
            quoted_array(&self.plaintext)
        );
        let _ = writeln!(&mut output, "q = \"{}\"", self.q);
        output
    }

    /// Writes the witness to a target file path.
    pub fn write_to_path(&self, path: &Path) -> std::io::Result<()> {
        std::fs::write(path, self.to_toml())
    }
}

impl SonobeStateCommitmentWitness {
    /// Serializes the witness into Noir `Prover.toml` syntax.
    pub fn to_toml(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(&mut output, "commit_pk = \"{}\"", self.commit_pk);
        let _ = writeln!(&mut output, "commit_ct_in = \"{}\"", self.commit_ct_in);
        let _ = writeln!(&mut output, "commit_ct_out = \"{}\"", self.commit_ct_out);
        let _ = writeln!(&mut output, "session_id = \"{}\"", self.session_id);
        let _ = writeln!(
            &mut output,
            "sonobe_final_state_commitment = \"{}\"",
            self.sonobe_final_state_commitment
        );
        let _ = writeln!(
            &mut output,
            "cyclo_aggregate_commitment = \"{}\"",
            self.cyclo_aggregate_commitment
        );
        let _ = writeln!(
            &mut output,
            "sonobe_state_preimage = [{}]",
            quoted_array(&self.sonobe_state_preimage)
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
pub fn generate_aggregator_final_witness() -> AggregatorFinalWitness {
    let decrypt_share = generate_decrypt_share_witness();
    let d1_raw: Vec<Fr> = decrypt_share
        .d_i
        .iter()
        .map(|value| decimal_to_field(value))
        .collect();

    let mut d2_raw = vec![Fr::from(0u64); N];
    d2_raw[0] = Fr::from(7u64);
    d2_raw[1] = Fr::from(11u64);

    let mut d3_raw = vec![Fr::from(0u64); N];
    d3_raw[0] = Fr::from(13u64);
    d3_raw[1] = Fr::from(17u64);
    d3_raw[2] = Fr::from(19u64);

    let lambda_1 = Fr::from(3u64);
    let lambda_2 = -Fr::from(3u64);
    let lambda_3 = Fr::from(1u64);

    let plaintext_raw: Vec<Fr> = d1_raw
        .iter()
        .zip(&d2_raw)
        .zip(&d3_raw)
        .map(|((d1, d2), d3)| (lambda_1 * *d1) + (lambda_2 * *d2) + (lambda_3 * *d3))
        .collect();

    let plaintext_hash = rolling_digest_raw(&plaintext_raw);
    let d1_hash = rolling_digest_raw(&d1_raw);
    let d2_hash = rolling_digest_raw(&d2_raw);
    let d3_hash = rolling_digest_raw(&d3_raw);
    let dkg_root = decimal_to_field(&decrypt_share.dkg_root);
    let epoch = decimal_to_field(&decrypt_share.epoch);
    let participant_set_hash = Fr::from(777u64);
    let d_commitment = rolling_digest_8_raw(&[
        d1_hash,
        d2_hash,
        d3_hash,
        dkg_root,
        participant_set_hash,
        epoch,
        Fr::from(AGGREGATOR_N_PARTICIPANTS),
        Fr::from(AGGREGATOR_THRESHOLD),
    ]);

    let mut ciphertext_hash = decimal_to_field(&decrypt_share.ciphertext_hash);
    if ciphertext_hash == plaintext_hash {
        ciphertext_hash += Fr::from(1u64);
    }

    let mut aggregate_pk_hash = rolling_digest_8_raw(&[
        decimal_to_field(&decrypt_share.pk_i_hash),
        decimal_to_field(&decrypt_share.c1_hash),
        d1_hash,
        d2_hash,
        d3_hash,
        epoch,
        Fr::from(AGGREGATOR_N_PARTICIPANTS),
        Fr::from(99u64),
    ]);

    let q = loop {
        let r = rolling_digest_8_raw(&[
            ciphertext_hash,
            plaintext_hash,
            aggregate_pk_hash,
            dkg_root,
            epoch,
            participant_set_hash,
            d_commitment,
            Fr::from(0u64),
        ]);
        let denominator = r_pow_n(r) + Fr::from(1u64);
        if denominator == Fr::from(0u64) {
            aggregate_pk_hash += Fr::from(1u64);
            continue;
        }

        let lhs = eval_poly_raw(&plaintext_raw, r);
        let rhs = lambda_1 * eval_poly_raw(&d1_raw, r)
            + lambda_2 * eval_poly_raw(&d2_raw, r)
            + lambda_3 * eval_poly_raw(&d3_raw, r);
        break (rhs - lhs)
            * match denominator.inverse() {
                Some(inv) => inv,
                None => Fr::from(0u64),
            };
    };

    AggregatorFinalWitness {
        ciphertext_hash: field_to_decimal(ciphertext_hash),
        plaintext_hash: field_to_decimal(plaintext_hash),
        aggregate_pk_hash: field_to_decimal(aggregate_pk_hash),
        dkg_root: field_to_decimal(dkg_root),
        epoch: field_to_decimal(epoch),
        participant_set_hash: field_to_decimal(participant_set_hash),
        d_commitment: field_to_decimal(d_commitment),
        d1: d1_raw.into_iter().map(field_to_decimal).collect(),
        d2: d2_raw.into_iter().map(field_to_decimal).collect(),
        d3: d3_raw.into_iter().map(field_to_decimal).collect(),
        plaintext: plaintext_raw.into_iter().map(field_to_decimal).collect(),
        q: field_to_decimal(q),
    }
}

/// Generates a valid witness for the `sonobe_state_commitment` circuit.
pub fn generate_sonobe_state_commitment_witness() -> SonobeStateCommitmentWitness {
    let sonobe_state_preimage_raw = [
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

    SonobeStateCommitmentWitness {
        commit_pk: field_to_decimal(Fr::from(1u64)),
        commit_ct_in: field_to_decimal(Fr::from(2u64)),
        commit_ct_out: field_to_decimal(Fr::from(3u64)),
        session_id: field_to_decimal(Fr::from(1u64)),
        sonobe_final_state_commitment: field_to_decimal(poseidon_hash_4(
            &sonobe_state_preimage_raw,
        )),
        cyclo_aggregate_commitment: field_to_decimal(poseidon_hash_4(
            &cyclo_aggregate_preimage_raw,
        )),
        sonobe_state_preimage: sonobe_state_preimage_raw
            .into_iter()
            .map(field_to_decimal)
            .collect(),
        cyclo_aggregate_preimage: cyclo_aggregate_preimage_raw
            .into_iter()
            .map(field_to_decimal)
            .collect(),
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
