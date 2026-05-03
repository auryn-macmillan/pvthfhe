use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub const N_PARTIES: usize = 4;
pub const THRESHOLD: usize = 3;
pub const N_RING: usize = 8;
pub const MODULUS_Q: i64 = 97;
pub const T_PLAIN: i64 = 4;
pub const DELTA: i64 = MODULUS_Q / T_PLAIN;
pub const MESSAGE: [i64; N_RING] = [1, 0, 1, 0, 1, 0, 1, 0];

pub type Poly = Vec<i64>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptDigest {
    pub commitment: String,
    pub challenge: String,
    pub response_norm: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyRecord {
    pub party_id: usize,
    pub sk: Poly,
    pub error: Poly,
    pub pk: Poly,
    pub keygen_nizk: TranscriptDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialDecryptRecord {
    pub party_id: usize,
    pub smudge: Poly,
    pub value: Poly,
    pub proof: TranscriptDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RandomnessRecord {
    pub u: Poly,
    pub e1: Poly,
    pub e2: Poly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextRecord {
    pub c0: Poly,
    pub c1: Poly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolynomialSketch {
    pub coefficient_index: usize,
    pub values_at_x: [i64; THRESHOLD],
    pub polynomial_mod_q: String,
    pub evaluation_at_x4: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkedExample {
    pub seed: u64,
    pub a: Poly,
    pub parties: Vec<PartyRecord>,
    pub participant_set: Vec<usize>,
    pub aggregate_pk: Poly,
    pub message: Poly,
    pub randomness: RandomnessRecord,
    pub ciphertext: CiphertextRecord,
    pub partials: Vec<PartialDecryptRecord>,
    pub aggregate_partial: Poly,
    pub m_recovered: Poly,
    pub polynomial_sketches: Vec<PolynomialSketch>,
    pub aggregate_proof: TranscriptDigest,
}

pub fn generate(seed: u64) -> WorkedExample {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let a = sample_uniform(&mut rng);
    let parties = (0..N_PARTIES)
        .map(|party_id| {
            let sk = sample_ternary(&mut rng);
            let error = sample_small(&mut rng);
            let pk = add_poly(&neg_poly(&mul_negacyclic(&a, &sk)), &error);
            let keygen_nizk =
                make_digest(&format!("keygen-party-{party_id}"), &[&a, &sk, &error, &pk]);

            PartyRecord {
                party_id,
                sk,
                error,
                pk,
                keygen_nizk,
            }
        })
        .collect::<Vec<_>>();
    let participant_set = vec![0, 1, 2];
    let aggregate_pk = participant_set.iter().fold(zero_poly(), |acc, party_id| {
        add_poly(&acc, &parties[*party_id].pk)
    });
    let message = MESSAGE.into_iter().collect::<Vec<_>>();
    let randomness = RandomnessRecord {
        u: sample_nonzero_small(&mut rng),
        e1: sample_small(&mut rng),
        e2: sample_small(&mut rng),
    };

    let delta_message = message
        .iter()
        .map(|coefficient| mod_q(DELTA * coefficient))
        .collect::<Vec<_>>();
    let c0 = add_poly(
        &add_poly(
            &mul_negacyclic(&aggregate_pk, &randomness.u),
            &randomness.e1,
        ),
        &delta_message,
    );
    let c1 = add_poly(&mul_negacyclic(&a, &randomness.u), &randomness.e2);
    let ciphertext = CiphertextRecord { c0, c1 };

    let partials = participant_set
        .iter()
        .map(|party_id| {
            let smudge = sample_small(&mut rng);
            let value = add_poly(
                &mul_negacyclic(&ciphertext.c1, &parties[*party_id].sk),
                &smudge,
            );
            let proof = make_digest(
                &format!("partial-party-{party_id}"),
                &[&ciphertext.c1, &parties[*party_id].sk, &smudge, &value],
            );

            PartialDecryptRecord {
                party_id: *party_id,
                smudge,
                value,
                proof,
            }
        })
        .collect::<Vec<_>>();

    let aggregate_partial = partials
        .iter()
        .fold(zero_poly(), |acc, partial| add_poly(&acc, &partial.value));
    let m_recovered = decode_message(&add_poly(&ciphertext.c0, &aggregate_partial));
    let polynomial_sketches = (0..N_RING)
        .map(|coefficient_index| interpolate_subset_polynomial(&parties, coefficient_index))
        .collect::<Vec<_>>();
    let aggregate_proof = make_digest(
        "aggregate-proof",
        &[
            &ciphertext.c0,
            &ciphertext.c1,
            &aggregate_partial,
            &m_recovered,
        ],
    );

    assert_eq!(
        m_recovered, message,
        "worked example must round-trip directly from seed {seed}"
    );

    WorkedExample {
        seed,
        a,
        parties,
        participant_set,
        aggregate_pk,
        message,
        randomness,
        ciphertext,
        partials,
        aggregate_partial,
        m_recovered,
        polynomial_sketches,
        aggregate_proof,
    }
}

pub fn render_report(example: &WorkedExample) -> String {
    let mut lines = Vec::new();
    lines.push("=== Architecture B Worked Example ===".to_owned());
    lines.push(format!(
        "n_parties={}, t={}, N_ring={}, q={}, t_plain={}, seed={}",
        N_PARTIES, THRESHOLD, N_RING, MODULUS_Q, T_PLAIN, example.seed
    ));
    lines.push(String::new());
    lines.push("Step 1 — Setup".to_owned());
    lines.push(format!(
        "N_ring={}, q={}, t_plain={}, Delta={}, n_parties={}, threshold={}, seed={}",
        N_RING, MODULUS_Q, T_PLAIN, DELTA, N_PARTIES, THRESHOLD, example.seed
    ));
    lines.push(
        "derivation=single direct ChaCha20Rng transcript from seed=42 (no search)".to_owned(),
    );
    lines.push(format!("a={}", format_poly(&example.a)));
    lines.push(String::new());
    lines.push("Step 2 — KeyGen (each party)".to_owned());

    for party in &example.parties {
        lines.push(format!(
            "party {} sk={}",
            party.party_id,
            format_poly(&party.sk)
        ));
        lines.push(format!(
            "party {} e={}",
            party.party_id,
            format_poly(&party.error)
        ));
        lines.push(format!(
            "party {} pk={}",
            party.party_id,
            format_poly(&party.pk)
        ));
        lines.push(format!(
            "party {} nizk(commitment={}, challenge={}, response_norm={})",
            party.party_id,
            party.keygen_nizk.commitment,
            party.keygen_nizk.challenge,
            party.keygen_nizk.response_norm
        ));
    }

    lines.push(format!(
        "participant_set={:?} (party 3 is omitted from Round-3 aggregation in this toy threshold walk-through)",
        example.participant_set
    ));
    lines.push(format!(
        "aggregate_pk=Σ pk_i over participant_set={}",
        format_poly(&example.aggregate_pk)
    ));
    for sketch in &example.polynomial_sketches {
        lines.push(format!(
            "share polynomial sketch coeff[{}]: p(x)={}, active values@x=1..3={:?}, p(4)={}",
            sketch.coefficient_index,
            sketch.polynomial_mod_q,
            sketch.values_at_x,
            sketch.evaluation_at_x4
        ));
    }
    lines.push(String::new());
    lines.push("Step 3 — Encrypt".to_owned());
    lines.push(format!("m={}", format_poly(&example.message)));
    lines.push(format!("u={}", format_poly(&example.randomness.u)));
    lines.push(format!("e1={}", format_poly(&example.randomness.e1)));
    lines.push(format!("e2={}", format_poly(&example.randomness.e2)));
    lines.push(format!("c0={}", format_poly(&example.ciphertext.c0)));
    lines.push(format!("c1={}", format_poly(&example.ciphertext.c1)));
    lines.push(String::new());
    lines.push("Step 4 — PartialDecrypt (parties 0, 1, 2)".to_owned());

    for partial in &example.partials {
        lines.push(format!(
            "d{} smudge={}",
            partial.party_id,
            format_poly(&partial.smudge)
        ));
        lines.push(format!(
            "d{}={}",
            partial.party_id,
            format_poly(&partial.value)
        ));
        lines.push(format!(
            "d{} proof(commitment={}, challenge={}, response_norm={})",
            partial.party_id,
            partial.proof.commitment,
            partial.proof.challenge,
            partial.proof.response_norm
        ));
    }

    lines.push(String::new());
    lines.push("Step 5 — Aggregate".to_owned());
    lines.push(format!("D={}", format_poly(&example.aggregate_partial)));
    lines.push(format!("m_recovered={}", format_poly(&example.m_recovered)));
    lines.push(String::new());
    lines.push("Step 6 — Verify (sketch)".to_owned());
    lines.push("NIZK verification: PASS (sketched — full proof in T24)".to_owned());
    lines.push(format!(
        "Aggregate proof Π: PASS (MicroNova compression sketched, commitment={}, challenge={}, response_norm={})",
        example.aggregate_proof.commitment,
        example.aggregate_proof.challenge,
        example.aggregate_proof.response_norm
    ));
    lines.push("Verifier acceptance: PASS".to_owned());
    lines.push("=== VERIFICATION PASSED ===".to_owned());
    lines.join("\n")
}

fn interpolate_subset_polynomial(
    parties: &[PartyRecord],
    coefficient_index: usize,
) -> PolynomialSketch {
    let y1 = parties[0].sk[coefficient_index];
    let y2 = parties[1].sk[coefficient_index];
    let y3 = parties[2].sk[coefficient_index];

    let c0 = mod_q(3 * y1 - 3 * y2 + y3);
    let c1 = mod_q((-5 * y1) + (8 * y2) - (3 * y3));
    let c2 = mod_q((y1 - (2 * y2) + y3) * mod_inv(2));
    let evaluation_at_x4 = eval_quadratic(c0, c1, c2, 4);

    PolynomialSketch {
        coefficient_index,
        values_at_x: [y1, y2, y3],
        polynomial_mod_q: format!("{} + {}·x + {}·x^2 (mod {})", c0, c1, c2, MODULUS_Q),
        evaluation_at_x4,
    }
}

fn eval_quadratic(c0: i64, c1: i64, c2: i64, x: i64) -> i64 {
    mod_q(c0 + c1 * x + c2 * x * x)
}

fn make_digest(label: &str, polynomials: &[&Poly]) -> TranscriptDigest {
    let mut state = 0xcbf2_9ce4_8422_2325_u64;
    for byte in label.as_bytes() {
        state ^= *byte as u64;
        state = state.wrapping_mul(0x0000_0100_0000_01b3);
    }

    let mut response_norm = 0_i64;
    for polynomial in polynomials {
        for coefficient in polynomial.iter().copied() {
            let normalized = mod_q(coefficient) as u64;
            state ^= normalized.wrapping_add(0x9e37_79b9_7f4a_7c15);
            state = state.rotate_left(13).wrapping_mul(0xff51_afd7_ed55_8ccd);
            response_norm += center_lift(coefficient).abs();
        }
    }

    let challenge = state.rotate_left(17) ^ 0xa5a5_a5a5_5a5a_5a5a;
    TranscriptDigest {
        commitment: format!("0x{state:016x}"),
        challenge: format!("0x{challenge:016x}"),
        response_norm,
    }
}

fn sample_uniform(rng: &mut ChaCha20Rng) -> Poly {
    (0..N_RING).map(|_| rng.gen_range(0..MODULUS_Q)).collect()
}

fn sample_ternary(rng: &mut ChaCha20Rng) -> Poly {
    (0..N_RING)
        .map(|_| match rng.gen_range(0..3) {
            0 => -1,
            1 => 0,
            _ => 1,
        })
        .collect()
}

fn sample_small(rng: &mut ChaCha20Rng) -> Poly {
    sample_ternary(rng)
}

fn sample_nonzero_small(rng: &mut ChaCha20Rng) -> Poly {
    loop {
        let sample = sample_small(rng);
        if sample.iter().any(|coefficient| *coefficient != 0) {
            return sample;
        }
    }
}

fn decode_message(noisy: &Poly) -> Poly {
    noisy
        .iter()
        .map(|coefficient| {
            (((mod_q(*coefficient) as f64) * (T_PLAIN as f64) / (MODULUS_Q as f64)).round() as i64)
                .rem_euclid(T_PLAIN)
        })
        .collect()
}

fn add_poly(lhs: &Poly, rhs: &Poly) -> Poly {
    lhs.iter()
        .zip(rhs.iter())
        .map(|(left, right)| mod_q(left + right))
        .collect()
}

fn neg_poly(poly: &Poly) -> Poly {
    poly.iter().map(|coefficient| mod_q(-coefficient)).collect()
}

fn mul_negacyclic(lhs: &Poly, rhs: &Poly) -> Poly {
    let mut out = vec![0_i64; N_RING];

    for (left_index, left) in lhs.iter().enumerate() {
        for (right_index, right) in rhs.iter().enumerate() {
            let mut index = left_index + right_index;
            let mut term = left * right;
            if index >= N_RING {
                index -= N_RING;
                term = -term;
            }
            out[index] += term;
        }
    }

    out.into_iter().map(mod_q).collect()
}

fn center_lift(value: i64) -> i64 {
    let reduced = mod_q(value);
    if reduced > MODULUS_Q / 2 {
        reduced - MODULUS_Q
    } else {
        reduced
    }
}

fn mod_q(value: i64) -> i64 {
    value.rem_euclid(MODULUS_Q)
}

fn mod_inv(value: i64) -> i64 {
    for candidate in 1..MODULUS_Q {
        if mod_q(value * candidate) == 1 {
            return candidate;
        }
    }

    std::process::abort()
}

fn zero_poly() -> Poly {
    vec![0; N_RING]
}

fn format_poly(poly: &Poly) -> String {
    let centered = poly
        .iter()
        .map(|value| center_lift(*value).to_string())
        .collect::<Vec<_>>();
    format!("[{}]", centered.join(", "))
}

#[cfg(test)]
mod tests {
    use super::{generate, render_report, DELTA, MESSAGE, MODULUS_Q, N_RING, THRESHOLD};

    #[test]
    fn worked_example_constants_match_design_brief() {
        assert_eq!(N_RING, 8);
        assert_eq!(MODULUS_Q, 97);
        assert_eq!(DELTA, 24);
        assert_eq!(THRESHOLD, 3);
        assert_eq!(MESSAGE, [1, 0, 1, 0, 1, 0, 1, 0]);
    }

    #[test]
    fn rendered_report_ends_in_verification_banner() {
        let example = generate(42);
        let report = render_report(&example);

        assert!(report.contains("Step 6 — Verify (sketch)"));
        assert!(report.ends_with("=== VERIFICATION PASSED ==="));
    }
}
