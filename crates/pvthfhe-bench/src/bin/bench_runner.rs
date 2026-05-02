use pvthfhe_bench::{BenchEnv, BenchResult};
use std::time::Instant;

fn main() {
    let env = BenchEnv::capture();

    let n_runs = 100u64;
    let mut times: Vec<f64> = Vec::with_capacity(n_runs as usize);

    for _ in 0..n_runs {
        let start = Instant::now();
        std::hint::black_box(42u64);
        times.push(start.elapsed().as_nanos() as f64);
    }

    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean_ns = times.iter().sum::<f64>() / n_runs as f64;
    let median_ns = times[n_runs as usize / 2];
    let p99_ns = times[(n_runs as usize * 99) / 100];
    let variance = times.iter().map(|t| (t - mean_ns).powi(2)).sum::<f64>() / n_runs as f64;
    let stddev_ns = variance.sqrt();

    let result = BenchResult {
        name: "noop".to_string(),
        mean_ns,
        median_ns,
        p99_ns,
        stddev_ns,
        n_runs,
        env,
    };

    println!("{}", serde_json::to_string(&result).unwrap());
}
