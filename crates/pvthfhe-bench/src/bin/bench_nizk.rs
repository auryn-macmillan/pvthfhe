/// P1 lattice NIZK benchmark: prove/verify/batch_verify for n=128, 512, 1024.
///
/// Outputs JSON result files to bench/p1/results-{n}.json.
use pvthfhe_fhe::real_nizk::{LatticeNizk, NizkStatement, NizkWitness, RealNizkAdapter};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

const Q: u64 = 65537;
const ERROR_BOUND: u64 = 17;
const ITERATIONS: usize = 100;
const BATCH_SIZES: [usize; 3] = [1, 10, 100];

#[derive(Serialize)]
struct BenchResult {
    scheme: String,
    n: usize,
    q: u64,
    error_bound: u64,
    iterations: usize,
    median_prove_ms: f64,
    median_verify_ms: f64,
    proof_size_bytes: usize,
    #[serde(rename = "batch_verify_1_ms")]
    batch_verify_1_ms: f64,
    #[serde(rename = "batch_verify_10_ms")]
    batch_verify_10_ms: f64,
    #[serde(rename = "batch_verify_100_ms")]
    batch_verify_100_ms: f64,
    #[serde(rename = "batch_verify_100_ms_per_proof")]
    batch_verify_100_ms_per_proof: f64,
}

fn pvss_commitment(session_id: &str, participant_id: u16, secret_value: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(session_id.as_bytes());
    h.update(participant_id.to_le_bytes());
    h.update(secret_value.to_be_bytes());
    h.finalize().into()
}

fn make_statement_witness(n: usize, rng: &mut ChaCha20Rng) -> (NizkStatement, NizkWitness) {
    use rand_core::RngCore;

    let session_id = format!("bench-session-n{}", n);
    let participant_id: u16 = 1;
    let secret_share: u64 = rng.next_u64() % Q;

    let error: Vec<i64> = (0..n)
        .map(|_| {
            let raw = rng.next_u64() % (ERROR_BOUND * 2 + 1);
            raw as i64 - ERROR_BOUND as i64
        })
        .collect();

    let mut randomness = vec![0u8; 32];
    rng.fill_bytes(&mut randomness);

    let mut ciphertext_bytes = vec![0u8; n];
    rng.fill_bytes(&mut ciphertext_bytes);

    let mut decrypt_share_bytes = vec![0u8; n];
    rng.fill_bytes(&mut decrypt_share_bytes);

    let commitment = pvss_commitment(&session_id, participant_id, secret_share);

    let stmt = NizkStatement {
        ciphertext_bytes,
        decrypt_share_bytes,
        pvss_commitment: commitment,
        params: (Q, n, ERROR_BOUND),
        session_id,
        participant_id,
    };

    let witness = NizkWitness {
        secret_share,
        error,
        randomness,
    };

    (stmt, witness)
}

fn median_duration(mut samples: Vec<Duration>) -> f64 {
    samples.sort();
    let mid = samples.len() / 2;
    if samples.len() % 2 == 0 {
        (samples[mid - 1] + samples[mid]).as_secs_f64() * 500.0
    } else {
        samples[mid].as_secs_f64() * 1000.0
    }
}

fn bench_n(n: usize) -> BenchResult {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Pre-generate statements and witnesses
    let pairs: Vec<(NizkStatement, NizkWitness)> = (0..ITERATIONS)
        .map(|_| make_statement_witness(n, &mut rng))
        .collect();

    // --- Prove timing ---
    let mut prove_times = Vec::with_capacity(ITERATIONS);
    let mut proofs = Vec::with_capacity(ITERATIONS);
    for (stmt, witness) in &pairs {
        let mut prng = ChaCha20Rng::from_seed([7u8; 32]);
        let t0 = Instant::now();
        let proof = RealNizkAdapter::prove(stmt, witness, &mut prng).expect("prove failed");
        prove_times.push(t0.elapsed());
        proofs.push(proof);
    }
    let proof_size_bytes = proofs[0].proof_bytes.len();
    let median_prove_ms = median_duration(prove_times);

    // --- Verify timing ---
    let mut verify_times = Vec::with_capacity(ITERATIONS);
    for (i, (stmt, _)) in pairs.iter().enumerate() {
        let t0 = Instant::now();
        RealNizkAdapter::verify(stmt, &proofs[i]).expect("verify failed");
        verify_times.push(t0.elapsed());
    }
    let median_verify_ms = median_duration(verify_times);

    // --- Batch verify timing ---
    let mut batch_results = [0.0f64; 3];
    for (idx, &bs) in BATCH_SIZES.iter().enumerate() {
        let batch_stmts: Vec<NizkStatement> = pairs[..bs].iter().map(|(s, _)| s.clone()).collect();
        let batch_proofs = proofs[..bs].to_vec();
        let t0 = Instant::now();
        RealNizkAdapter::batch_verify(&batch_stmts, &batch_proofs).expect("batch_verify failed");
        batch_results[idx] = t0.elapsed().as_secs_f64() * 1000.0;
    }

    BenchResult {
        scheme: "pvthfhe-p1-slap".to_string(),
        n,
        q: Q,
        error_bound: ERROR_BOUND,
        iterations: ITERATIONS,
        median_prove_ms,
        median_verify_ms,
        proof_size_bytes,
        batch_verify_1_ms: batch_results[0],
        batch_verify_10_ms: batch_results[1],
        batch_verify_100_ms: batch_results[2],
        batch_verify_100_ms_per_proof: batch_results[2] / 100.0,
    }
}

fn main() {
    // Ensure output directory exists
    std::fs::create_dir_all("bench/p1").expect("create bench/p1");

    for &n in &[128usize, 512, 1024] {
        eprintln!("[bench_nizk] n={} ...", n);
        let result = bench_n(n);
        let json = serde_json::to_string_pretty(&result).expect("serialize");

        let path = format!("bench/p1/results-{}.json", n);
        std::fs::write(&path, &json).expect("write json");
        eprintln!("[bench_nizk] wrote {}", path);
        eprintln!(
            "  prove={:.3}ms  verify={:.3}ms  size={}B  batch100={:.3}ms ({:.4}ms/proof)",
            result.median_prove_ms,
            result.median_verify_ms,
            result.proof_size_bytes,
            result.batch_verify_100_ms,
            result.batch_verify_100_ms_per_proof,
        );
    }
    eprintln!("[bench_nizk] done.");
}
