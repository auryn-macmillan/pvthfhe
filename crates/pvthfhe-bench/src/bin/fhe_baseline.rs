use pvthfhe_aggregator::keygen::simulator::{KeygenResult, KeygenSimulator};
use pvthfhe_fhe::{fhers::FhersBackend, FheBackend, FheError};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::{
    env, fs,
    path::Path,
    time::{Duration, Instant},
};

const CANONICAL_PARAMS_TOML: &str =
    "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";
const DEFAULT_NS: [usize; 7] = [4, 8, 16, 32, 64, 128, 256];
const MAX_SINGLE_RUN: Duration = Duration::from_secs(300);
const PLAINTEXT: &[u8] = b"benchmark plaintext";
const CSV_PATH: &str = "bench/results/fhe-baseline.csv";
const MARKDOWN_PATH: &str = "bench/results/fhe-baseline.md";

#[derive(Clone, Debug)]
struct BenchRow {
    n: usize,
    t: usize,
    keygen_total_s: f64,
    keygen_per_party_s: f64,
    encrypt_s: f64,
    partial_decrypt_per_party_s: f64,
    aggregate_decrypt_s: f64,
    peak_rss_mb: u64,
}

fn elapsed_seconds(started: Instant) -> f64 {
    started.elapsed().as_secs_f64()
}

fn selected_ns() -> Vec<usize> {
    let n_max = env::var("FHE_BENCH_N_MAX")
        .ok()
        .and_then(|value| value.parse::<usize>().ok());

    DEFAULT_NS
        .into_iter()
        .filter(|n| n_max.is_none_or(|max| *n <= max))
        .collect()
}

fn read_peak_rss_mb() -> u64 {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return 0;
    };

    status
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u64>().ok())
        .map(|kb| kb / 1024)
        .unwrap_or(0)
}

fn run_benchmark(n: usize, t: usize) -> Result<BenchRow, FheError> {
    let overall_started = Instant::now();
    let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML)?;
    let backend_threshold = t.min((n + 1) / 2);

    let keygen_started = Instant::now();
    let mut simulator = KeygenSimulator::new_with_backend(n, backend_threshold, backend.clone())
        .map_err(|e| FheError::Backend {
            reason: format!("keygen new: {e}"),
        })?;
    let transcript = match simulator.run()? {
        KeygenResult::Complete(transcript) => transcript,
        KeygenResult::Blamed(blamed) => {
            return Err(FheError::Backend {
                reason: format!("keygen blamed parties: {blamed:?}"),
            });
        }
    };
    backend.setup_threshold(n, backend_threshold)?;
    let keygen_total_s = elapsed_seconds(keygen_started);

    let aggregate_pk = transcript.round3_aggregate.aggregate_pk;

    let encrypt_started = Instant::now();
    let mut encrypt_rng = ChaCha20Rng::seed_from_u64(0xE100_0000 + n as u64);
    let ciphertext = backend.encrypt(&aggregate_pk, PLAINTEXT, &mut encrypt_rng)?;
    let encrypt_s = elapsed_seconds(encrypt_started);

    let partial_started = Instant::now();
    let mut shares = Vec::with_capacity(t);
    for party_index in 1..=t {
        let party_id = u32::try_from(party_index).map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;
        let mut rng = ChaCha20Rng::seed_from_u64((n as u64) << 32 | u64::from(party_id));
        shares.push(backend.partial_decrypt(&ciphertext, party_id, &mut rng)?);
    }
    let partial_decrypt_total_s = elapsed_seconds(partial_started);

    let aggregate_started = Instant::now();
    let recovered = backend.aggregate_decrypt(&ciphertext, &shares, backend_threshold, b"")?;
    let aggregate_decrypt_s = elapsed_seconds(aggregate_started);
    if recovered != PLAINTEXT {
        panic!(
            "aggregate_decrypt roundtrip failed at n={}: expected {:?}, got {:?}",
            n, PLAINTEXT, recovered
        );
    }

    if overall_started.elapsed() > MAX_SINGLE_RUN {
        return Err(FheError::Backend {
            reason: format!("benchmark exceeded {}s budget", MAX_SINGLE_RUN.as_secs()),
        });
    }

    Ok(BenchRow {
        n,
        t,
        keygen_total_s,
        keygen_per_party_s: keygen_total_s / n as f64,
        encrypt_s,
        partial_decrypt_per_party_s: partial_decrypt_total_s / t as f64,
        aggregate_decrypt_s,
        peak_rss_mb: read_peak_rss_mb(),
    })
}

fn csv_contents(rows: &[BenchRow]) -> String {
    let mut out = String::from(
        "n,t,keygen_total_s,keygen_per_party_s,encrypt_s,partial_decrypt_per_party_s,aggregate_decrypt_s,peak_rss_mb\n",
    );

    for row in rows {
        out.push_str(&format!(
            "{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{}\n",
            row.n,
            row.t,
            row.keygen_total_s,
            row.keygen_per_party_s,
            row.encrypt_s,
            row.partial_decrypt_per_party_s,
            row.aggregate_decrypt_s,
            row.peak_rss_mb
        ));
    }

    out
}

fn markdown_contents(rows: &[BenchRow]) -> String {
    let mut out = String::from(
        "# FHE baseline benchmark\n\n## Results\n\n| n | t | keygen_total_s | keygen_per_party_s | encrypt_s | partial_decrypt_per_party_s | aggregate_decrypt_s | peak_rss_mb |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n",
    );

    for row in rows {
        out.push_str(&format!(
            "| {} | {} | {:.6} | {:.6} | {:.6} | {:.6} | {:.6} | {} |\n",
            row.n,
            row.t,
            row.keygen_total_s,
            row.keygen_per_party_s,
            row.encrypt_s,
            row.partial_decrypt_per_party_s,
            row.aggregate_decrypt_s,
            row.peak_rss_mb
        ));
    }

    out.push_str("\n## ASCII keygen trend\n\n```text\n");
    for row in rows {
        let bars = (row.keygen_total_s.max(0.001) * 10.0).ceil() as usize;
        out.push_str(&format!(
            "n={:<3} {} {:.3}s\n",
            row.n,
            "#".repeat(bars),
            row.keygen_total_s
        ));
    }
    out.push_str("```\n");

    out
}

fn main() {
    fs::create_dir_all(Path::new("bench/results")).expect("create bench/results");

    let mut rows = Vec::new();
    for n in selected_ns() {
        let t = (2 * n + 2) / 3;
        match run_benchmark(n, t) {
            Ok(row) => {
                eprintln!(
                    "n={} t={} keygen_total_s={:.3} encrypt_s={:.3}",
                    row.n, row.t, row.keygen_total_s, row.encrypt_s
                );
                rows.push(row);
            }
            Err(error) => {
                eprintln!("n={n} skipped: {error}");
                break;
            }
        }
    }

    fs::write(CSV_PATH, csv_contents(&rows)).expect("write benchmark CSV");
    fs::write(MARKDOWN_PATH, markdown_contents(&rows)).expect("write benchmark Markdown");
}
