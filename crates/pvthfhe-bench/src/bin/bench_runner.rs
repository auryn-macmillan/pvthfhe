use pvthfhe_bench::{
    backends::{expected_rns_len, fhe_rs::FheRsBackend, POLY_DEGREE, RqOps},
    BenchEnv, BenchRecord, summarize_samples,
};
use std::{hint::black_box, time::Instant};

const N_RUNS: u64 = 12;

fn time_case<F>(mut f: F) -> Vec<f64>
where
    F: FnMut(),
{
    let mut samples = Vec::with_capacity(N_RUNS as usize);
    for _ in 0..N_RUNS {
        let start = Instant::now();
        f();
        samples.push(start.elapsed().as_nanos() as f64);
    }
    samples
}

fn emit_record(case: &str, backend: &str, samples: &[f64]) {
    let stats = summarize_samples(samples);
    let record = BenchRecord {
        case: case.to_owned(),
        backend: backend.to_owned(),
        median_ns: stats.median_ns,
        mean_ns: stats.mean_ns,
        stddev_ns: stats.stddev_ns,
        n_runs: N_RUNS,
    };

    println!("{}", serde_json::to_string(&record).unwrap());
}

fn main() {
    let _env = BenchEnv::capture();
    let backend = FheRsBackend;

    let forward_samples = time_case(|| {
        let mut coeffs = vec![0_u64; POLY_DEGREE];
        backend.sample_uniform(&mut coeffs, 1);
        backend.ntt_fwd(black_box(&mut coeffs));
    });
    emit_record("ntt_forward(N=4096,q=q0)", "fhe_rs", &forward_samples);

    let inverse_samples = time_case(|| {
        let mut coeffs = vec![0_u64; POLY_DEGREE];
        backend.sample_uniform(&mut coeffs, 2);
        backend.ntt_fwd(&mut coeffs);
        backend.ntt_inv(black_box(&mut coeffs));
    });
    emit_record("ntt_inverse(N=4096,q=q0)", "fhe_rs", &inverse_samples);

    let mul_samples = time_case(|| {
        let mut lhs = vec![0_u64; expected_rns_len()];
        let mut rhs = vec![0_u64; expected_rns_len()];
        let mut out = vec![0_u64; expected_rns_len()];
        backend.sample_uniform(&mut lhs, 3);
        backend.sample_uniform(&mut rhs, 4);
        backend.poly_mul(black_box(&lhs), black_box(&rhs), black_box(&mut out));
    });
    emit_record(
        "poly_mul_ntt_domain(N=4096,RNS={q0..q3})",
        "fhe_rs",
        &mul_samples,
    );

    let sample_samples = time_case(|| {
        let mut out = vec![0_u64; expected_rns_len()];
        backend.sample_uniform(black_box(&mut out), 5);
    });
    emit_record(
        "sample_uniform_rq(N=4096,RNS={q0..q3})",
        "fhe_rs",
        &sample_samples,
    );
}
