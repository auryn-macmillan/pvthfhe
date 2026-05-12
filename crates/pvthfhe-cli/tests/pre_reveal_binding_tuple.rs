use std::fs;

const PIPELINE_PATH: &str = "src/full_pipeline.rs";

const REQUIRED_BINDING_FIELDS: &[&str] = &[
    "session_id",
    "epoch",
    "ct_hash",
    "roster_hash",
    "param_hash",
    "srsHash",
    "dkg_root",
];

/// Assert each required binding field appears in the pre-reveal binding
/// hasher construction in full_pipeline.rs.
///
/// After GREEN, `build_fold_instances` (or equivalent) must hash the full
/// tuple: (session_id, epoch, ct_hash, roster_hash, param_hash, srsHash, dkg_root).
/// Missing any field makes the binding incomplete — a malicious aggregator
/// could substitute shares across sessions or epochs.
#[test]
fn pre_reveal_binding_commits_full_tuple() {
    let src = fs::read_to_string(PIPELINE_PATH).expect("full_pipeline.rs must be readable");

    // Find the binding hasher construction segment (Sha256::new() ... finalize())
    let hasher_start = src
        .find("binding_hasher")
        .or_else(|| src.find("Sha256::new"))
        .or_else(|| src.find("pre_reveal"))
        .or_else(|| src.find("binding"));

    // There must be a binding construction somewhere
    assert!(
        hasher_start.is_some(),
        "No pre-reveal binding hasher found in {PIPELINE_PATH}. \
         Expected a Sha256 hasher binding the full tuple \
         (session_id, epoch, ct_hash, roster_hash, param_hash, srsHash, dkg_root)."
    );

    let start = hasher_start.unwrap();
    let end = (start + 3000).min(src.len());
    let binding_region = &src[start..end];

    let mut missing = Vec::new();
    for field in REQUIRED_BINDING_FIELDS {
        if !binding_region.contains(field) {
            missing.push(*field);
        }
    }

    assert!(
        missing.is_empty(),
        "Pre-reveal binding in {PIPELINE_PATH} is missing required fields: {:?}. \
         Region inspected (from offset {}): ...{}... \
         The binding must commit the full tuple atomically.",
        missing,
        start,
        &binding_region[..binding_region.len().min(300)]
    );
}

/// RED: ensure the binding tuple check detects missing fields on current code.
/// This test exists to document which fields ARE present now.
#[test]
fn binding_currently_missing_fields() {
    let src = fs::read_to_string(PIPELINE_PATH).expect("full_pipeline.rs must be readable");

    let present: Vec<_> = REQUIRED_BINDING_FIELDS
        .iter()
        .filter(|field| {
            src.contains(&format!("binding_hasher.update({field}"))
                || src.contains(&format!("h.update({field}"))
                || src.contains(&format!(".update({field}"))
        })
        .copied()
        .collect();

    let missing: Vec<_> = REQUIRED_BINDING_FIELDS
        .iter()
        .filter(|f| !present.contains(f))
        .copied()
        .collect();

    // On current main, several fields should be missing — this is RED.
    assert!(
        !missing.is_empty(),
        "pre_reveal_binding_tuple: all {} required binding fields appear \
         present in {PIPELINE_PATH}: {:?}. If this passes, the GREEN fix \
         may already be in place, or the field names need updating.",
        REQUIRED_BINDING_FIELDS.len(),
        present
    );

    eprintln!("Current binding present fields: {:?}", present);
    eprintln!("Current binding MISSING fields: {:?}", missing);
}
