use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn csv_path() -> PathBuf {
    repo_root().join("bench/results/fhe-baseline.csv")
}

fn markdown_path() -> PathBuf {
    repo_root().join("bench/results/fhe-baseline.md")
}

#[test]
fn baseline_smoke_generates_csv_rows_and_monotone_timings() {
    let _ = fs::remove_file(csv_path());
    let _ = fs::remove_file(markdown_path());

    let status = Command::new(env!("CARGO_BIN_EXE_fhe_baseline"))
        .current_dir(repo_root())
        .env("FHE_BENCH_N_MAX", "16")
        .status()
        .expect("run fhe_baseline binary");

    assert!(status.success(), "fhe_baseline should exit successfully");

    let csv = fs::read_to_string(csv_path()).expect("benchmark should write CSV results");
    let markdown =
        fs::read_to_string(markdown_path()).expect("benchmark should write Markdown results");

    assert!(
        csv.starts_with(
            "n,t,keygen_total_s,keygen_per_party_s,encrypt_s,partial_decrypt_per_party_s,aggregate_decrypt_s,peak_rss_mb"
        ),
        "CSV should contain the required header: {csv}"
    );
    assert!(
        markdown.contains("benchmark"),
        "Markdown output should not be empty"
    );

    let rows = csv.lines().skip(1).collect::<Vec<_>>();
    assert!(
        rows.len() >= 3,
        "expected at least 3 data rows, got {rows:?}"
    );

    let mut first_keygen = None::<f64>;
    let mut last_keygen = None::<f64>;
    let mut seen_ns = Vec::new();

    for row in rows {
        let columns = row.split(',').collect::<Vec<_>>();
        assert_eq!(columns.len(), 8, "expected 8 CSV columns in row: {row}");
        let n = columns[0].parse::<usize>().expect("n should parse");
        let keygen_total_s = columns[2]
            .parse::<f64>()
            .expect("keygen_total_s should parse as f64");
        seen_ns.push(n);

        if n == 4 {
            first_keygen = Some(keygen_total_s);
        }
        if n == 16 {
            last_keygen = Some(keygen_total_s);
        }
    }

    assert!(
        seen_ns.contains(&4) && seen_ns.contains(&8) && seen_ns.contains(&16),
        "expected benchmark rows for n=4,8,16, got {seen_ns:?}"
    );
    assert!(
        last_keygen.expect("missing n=16 row") >= first_keygen.expect("missing n=4 row"),
        "expected monotone keygen timing between n=4 and n=16"
    );
}
