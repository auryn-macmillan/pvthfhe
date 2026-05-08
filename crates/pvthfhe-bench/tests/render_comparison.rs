use pvthfhe_bench::render_comparison::{
    render_comparison_markdown, report_output_path, BackendIds, BaselineCircuitTiming,
    BaselineEnvelope, BaselineProvenance, ComparisonCircuitTiming, ComparisonEnvelope,
    ComparisonTarget, HardwareDisclosure, PhaseTotals,
};

fn synthetic_comparison() -> ComparisonEnvelope {
    ComparisonEnvelope {
        circuit_timings: vec![
            row("ZkPkBfv", None, "n/a", "1:N", 0, "aggregate-of-N keygen mapping", Some("not wired")),
            row("ZkShareComputation", None, "n/a", "1:1", 0, "dealer-local share computation", Some("not wired")),
            row("ZkShareEncryption", Some(285.0), "real", "1:N(N-1)", 3, "per-pair PVSS share-encryption proof", Some("vk unavailable")),
            row("ZkVerifyShareProofs", None, "n/a", "1:N(N-1)", 0, "per-pair verifier-side proof checks", Some("not wired")),
            row("ZkNodeDkgFold", None, "n/a", "2:2 split-merge", 0, "merged Cyclo fold", Some("not wired")),
            row("ZkPkAggregation", None, "n/a", "2:2 split-merge", 0, "merged Cyclo fold", Some("not wired")),
            row("ZkDkgAggregation", None, "surrogate", "1:1", 0, "proof-system asymmetry applies", Some("surrogate timing")),
            row("ZkThresholdShareDecryption", None, "n/a", "1:N", 0, "aggregate-of-N decrypt proof mapping", Some("not wired")),
            row("ZkDkgShareDecryption", None, "n/a", "1:N", 0, "per-party decrypt-side PVSS proof", Some("not wired")),
            row("ZkDecryptedSharesAggregation", None, "n/a", "2:2 split-merge", 0, "merged Cyclo+Sonobe aggregation", Some("not wired")),
            row("ZkDecryptionAggregation", None, "n/a", "2:2 split-merge", 0, "merged Cyclo+Sonobe aggregation", Some("not wired")),
            row("onchain_verify", None, "real-fallback", "1:1", 0, "proof-vs-attestation asymmetry", Some("NoGo path")),
        ],
        phase_totals: PhaseTotals {
            dkg_ms: Some(285.0),
            decrypt_ms: None,
            onchain_verify_ms: None,
            end_to_end_ms: Some(445.0),
        },
        hardware: HardwareDisclosure {
            cpu: "AMD RYZEN AI MAX+ 395 w/ Radeon 8060S".to_owned(),
            cpu_cores: 8,
            ram_gb: 62,
            kernel: "Linux version 6.8.0-111-generic".to_owned(),
        },
        backend_ids: BackendIds {
            fhe: "fhers-bfv".to_owned(),
            nizk: "cyclo-ajtai-d2-conditional".to_owned(),
            folding: "cyclo-rlwe-t10-lemma9-heuristic".to_owned(),
            compressor: "sonobe-nova-bn254-grumpkin".to_owned(),
            pvss: "lattice-pvss-bfv-d2".to_owned(),
        },
        commit_sha: "deadbee".to_owned(),
        comparison_target: ComparisonTarget {
            name: "Interfold integration_summary.json".to_owned(),
            source: "https://github.com/gnosisguild/enclave/tree/main/circuits/benchmarks/results_secure".to_owned(),
            n: 3,
            t: 1,
            seed: 1,
            dry_run: true,
        },
    }
}

fn synthetic_baseline() -> BaselineEnvelope {
    BaselineEnvelope {
        provenance: BaselineProvenance {
            source_url: "https://github.com/gnosisguild/enclave/tree/main/circuits/benchmarks/results_secure".to_owned(),
            source_commit: "c7e98029193f548ac4575fd05d007b034b75385c".to_owned(),
            retrieved: "2026-05-06".to_owned(),
            hardware: "Apple M4 Pro, 14c/48GB".to_owned(),
            toolchain: "Nargo 1.0.0-beta.16, BB 3.0.0-nightly.20260102".to_owned(),
            config: "H=N=3, T=1".to_owned(),
            estimation_method: "Heuristic proportional split of the published 8056 s total.".to_owned(),
        },
        circuit_timings: vec![
            baseline_row("ZkPkBfv", 161120.0),
            baseline_row("ZkShareComputation", 80560.0),
            baseline_row("ZkShareEncryption", 6042000.0),
            baseline_row("ZkVerifyShareProofs", 483360.0),
            baseline_row("ZkNodeDkgFold", 161120.0),
            baseline_row("ZkPkAggregation", 80560.0),
            baseline_row("ZkDkgAggregation", 241680.0),
            baseline_row("ZkThresholdShareDecryption", 241680.0),
            baseline_row("ZkDkgShareDecryption", 322240.0),
            baseline_row("ZkDecryptedSharesAggregation", 80560.0),
            baseline_row("ZkDecryptionAggregation", 80560.0),
            baseline_row("OnChainUltraHonkVerify", 80560.0),
        ],
    }
}

fn row(
    name: &str,
    prove_ms: Option<f64>,
    status: &str,
    cardinality_tag: &str,
    instances_run: usize,
    comparability_note: &str,
    gap_reason: Option<&str>,
) -> ComparisonCircuitTiming {
    ComparisonCircuitTiming {
        name: name.to_owned(),
        prove_ms,
        verify_ms: None,
        witness_ms: prove_ms,
        vk_kb: None,
        proof_kb: None,
        status: status.to_owned(),
        cardinality_tag: cardinality_tag.to_owned(),
        instances_run,
        comparability_note: comparability_note.to_owned(),
        gap_reason: gap_reason.map(str::to_owned),
    }
}

fn baseline_row(name: &str, ms: f64) -> BaselineCircuitTiming {
    BaselineCircuitTiming {
        name: name.to_owned(),
        ms,
        note: format!("Baseline note for {name}"),
    }
}

#[test]
fn renders_side_by_side_markdown_with_required_disclosures_and_rows() {
    let mut ours = synthetic_comparison();
    ours.hardware = HardwareDisclosure {
        cpu: "Synthetic CPU".to_owned(),
        cpu_cores: 8,
        ram_gb: 64,
        kernel: "Linux synthetic".to_owned(),
    };

    let markdown = render_comparison_markdown(&ours, &synthetic_baseline())
        .expect("render comparison markdown");

    assert!(
        markdown.contains("## Hardware & Toolchain Disclosure"),
        "missing hardware disclosure block: {markdown}"
    );
    assert!(
        markdown.contains("| Hardware | Synthetic CPU, 8 cores, 64 GB RAM, Linux synthetic |"),
        "missing our hardware disclosure row: {markdown}"
    );
    assert!(
        markdown.contains(
            "| Circuit | Cardinality | PVTHFHE (ms) | Interfold (ms) | Ratio | Status | Notes |"
        ),
        "missing ratio-bearing timing table header: {markdown}"
    );

    for circuit_name in [
        "ZkPkBfv",
        "ZkShareComputation",
        "ZkShareEncryption",
        "ZkVerifyShareProofs",
        "ZkNodeDkgFold",
        "ZkPkAggregation",
        "ZkDkgAggregation",
        "ZkThresholdShareDecryption",
        "ZkDkgShareDecryption",
        "ZkDecryptedSharesAggregation",
        "ZkDecryptionAggregation",
        "OnChainUltraHonkVerify",
    ] {
        assert!(
            markdown.contains(circuit_name),
            "missing circuit row for {circuit_name}: {markdown}"
        );
    }

    assert!(
        markdown.contains("## Status Legend"),
        "missing status legend section: {markdown}"
    );
    assert!(
        markdown.contains("`real`: proof system fully implemented"),
        "missing real status legend entry: {markdown}"
    );
    assert!(
        markdown.contains("`surrogate`: placeholder/mock — not comparable"),
        "missing surrogate status legend entry: {markdown}"
    );
    assert!(
        markdown.contains("No normalization applied"),
        "missing no-normalization disclosure: {markdown}"
    );
    assert!(
        markdown.contains("Interfold estimation method:"),
        "missing estimation method provenance: {markdown}"
    );
}

#[test]
fn report_output_path_rejects_non_sha_commit_ids() {
    let err = report_output_path(std::path::Path::new("bench/results"), "../../escape")
        .expect_err("path traversal commit id must fail");
    assert!(
        err.to_string().contains("invalid commit SHA"),
        "unexpected error: {err}"
    );
}
