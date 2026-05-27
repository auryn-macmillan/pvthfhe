pub struct CircuitMapping {
    pub interfold_name: &'static str,
    pub pvthfhe_name: &'static str,
    pub cardinality: &'static str,
    pub aggregation_rule: &'static str,
    pub gap_reason: Option<&'static str>,
    pub proof_system_note: Option<&'static str>,
}

pub const INTERFOLD_CIRCUIT_NAMES: [&str; 12] = [
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
];

pub const COMPARISON_ROW_NAMES: [&str; 12] = [
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
    "onchain_verify",
];

pub const CIRCUIT_MAP: &[CircuitMapping] = &[
    CircuitMapping {
        interfold_name: "ZkPkBfv",
        pvthfhe_name: "Sigma+Ajtai NIZK (keygen)",
        cardinality: "1:N",
        aggregation_rule: "sum",
        gap_reason: None,
        proof_system_note: None,
    },
    CircuitMapping {
        interfold_name: "ZkShareComputation",
        pvthfhe_name: "fhers::keygen_share_with_session",
        cardinality: "1:1",
        aggregation_rule: "n/a",
        gap_reason: None,
        proof_system_note: None,
    },
    CircuitMapping {
        interfold_name: "ZkShareEncryption",
        pvthfhe_name: "Lattice PVSS share-encryption proof",
        cardinality: "1:N(N-1)",
        aggregation_rule: "sum",
        gap_reason: None,
        proof_system_note: None,
    },
    CircuitMapping {
        interfold_name: "ZkVerifyShareProofs",
        pvthfhe_name: "PVSS encrypted-share proof verification",
        cardinality: "1:N(N-1)",
        aggregation_rule: "sum",
        gap_reason: None,
        proof_system_note: None,
    },
    CircuitMapping {
        interfold_name: "ZkNodeDkgFold",
        pvthfhe_name: "Cyclo first-fold + aggregation fold",
        cardinality: "2:2 split-merge",
        aggregation_rule: "sum",
        gap_reason: Some("merged into single PVTHFHE cyclo_fold pass"),
        proof_system_note: None,
    },
    CircuitMapping {
        interfold_name: "ZkPkAggregation",
        pvthfhe_name: "Cyclo first-fold + aggregation fold",
        cardinality: "2:2 split-merge",
        aggregation_rule: "sum",
        gap_reason: Some("merged into single PVTHFHE cyclo_fold pass"),
        proof_system_note: None,
    },
    CircuitMapping {
        interfold_name: "ZkDkgAggregation",
        pvthfhe_name: "Nova wrap",
        cardinality: "1:1",
        aggregation_rule: "n/a",
        gap_reason: None,
        proof_system_note: Some(
            "PVTHFHE uses a Nova wrap in place of Interfold's final UltraHonk aggregation over BFV state",
        ),
    },
    CircuitMapping {
        interfold_name: "ZkThresholdShareDecryption",
        pvthfhe_name: "Sigma+Ajtai NIZK (decrypt-time statement)",
        cardinality: "1:N",
        aggregation_rule: "sum",
        gap_reason: None,
        proof_system_note: None,
    },
    CircuitMapping {
        interfold_name: "ZkDkgShareDecryption",
        pvthfhe_name: "PVSS decrypt-side proof",
        cardinality: "1:N",
        aggregation_rule: "sum",
        gap_reason: None,
        proof_system_note: None,
    },
    CircuitMapping {
        interfold_name: "ZkDecryptedSharesAggregation",
        pvthfhe_name: "Cyclo + Nova decrypt aggregation",
        cardinality: "2:2 split-merge",
        aggregation_rule: "sum",
        gap_reason: Some("merged into single PVTHFHE aggregate_decrypt pass"),
        proof_system_note: None,
    },
    CircuitMapping {
        interfold_name: "ZkDecryptionAggregation",
        pvthfhe_name: "Cyclo + Nova decrypt aggregation",
        cardinality: "2:2 split-merge",
        aggregation_rule: "sum",
        gap_reason: Some("merged into single PVTHFHE aggregate_decrypt pass"),
        proof_system_note: Some(
            "PVTHFHE's final decrypt aggregation inherits the Nova-vs-Interfold proof-system asymmetry",
        ),
    },
    CircuitMapping {
        interfold_name: "OnChainUltraHonkVerify",
        pvthfhe_name: "BB UltraHonkVerifier.sol + PvtFheVerifier passthrough",
        cardinality: "1:1",
        aggregation_rule: "n/a",
        gap_reason: Some("real-fallback: measured via fallback compressor.verify proxy on the NoGo on-chain path"),
        proof_system_note: Some(
            "The comparison row is emitted as onchain_verify in PVTHFHE JSON even though Interfold's published circuit name is OnChainUltraHonkVerify",
        ),
    },
];

pub fn comparison_row_name(interfold_name: &str) -> &str {
    match interfold_name {
        "OnChainUltraHonkVerify" => "onchain_verify",
        _ => interfold_name,
    }
}

pub fn mapping_for(interfold_name: &str) -> Option<&'static CircuitMapping> {
    CIRCUIT_MAP
        .iter()
        .find(|mapping| mapping.interfold_name == interfold_name)
}

pub fn mapping_for_comparison_row(comparison_name: &str) -> Option<&'static CircuitMapping> {
    let interfold_name = match comparison_name {
        "onchain_verify" => "OnChainUltraHonkVerify",
        _ => comparison_name,
    };
    mapping_for(interfold_name)
}
