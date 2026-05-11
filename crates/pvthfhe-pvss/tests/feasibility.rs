//! Feasibility guard for the lattice PVSS spike.

use std::{
    collections::BTreeMap,
    env, fs,
    time::Instant,
    path::{Path, PathBuf},
};

use pvthfhe_nizk::{
    adapter::CycloNizkAdapter, hash_bridge, NizkAdapter, NizkStatement, NizkWitness,
};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn extract_front_matter(contents: &str) -> Option<&str> {
    let rest = contents.strip_prefix("---\n")?;
    let end = rest.find("\n---\n")?;
    Some(&rest[..end])
}

fn front_matter_map(front_matter: &str) -> BTreeMap<&str, &str> {
    front_matter
        .lines()
        .filter_map(|line| line.split_once(':').map(|(key, value)| (key.trim(), value.trim())))
        .collect()
}

fn sample_statement_and_witness() -> (NizkStatement, NizkWitness) {
    let session_id = "pvss-feasibility-toy".to_owned();
    let participant_id = 1u16;
    let secret_share = 7u64;
    let pvss_commitment = hash_bridge::commit(&session_id, participant_id, secret_share);
    let mut secret_share_poly = vec![0i64; 8192];
    secret_share_poly[0] = 1;
    secret_share_poly[3] = -1;
    secret_share_poly[9] = 1;
    let mut error = vec![0i64; 8192];
    error[0] = 1;
    error[5] = -1;
    error[12] = 2;

    (
        NizkStatement {
            ciphertext_bytes: vec![0x01, 0x02, 0x03, 0x04],
            decrypt_share_bytes: vec![0x0A, 0x0B, 0x0C, 0x0D],
            pvss_commitment,
            params: (174, 8192, 16),
            session_id,
            participant_id,
            epoch: 0,
        },
        NizkWitness {
            secret_share,
            secret_share_poly,
            error,
            randomness: vec![0xAA, 0xBB, 0xCC, 0xDD],
        },
    )
}

#[test]
fn lattice_pvss_feasibility_doc_exists_with_verdict_field() -> Result<(), Box<dyn std::error::Error>> {
    let doc_path = repo_root().join(".sisyphus/research/lattice-pvss-feasibility.md");
    let contents = fs::read_to_string(&doc_path)?;
    let front_matter = extract_front_matter(&contents).ok_or("missing YAML front matter")?;
    let front_matter = front_matter_map(front_matter);
    let verdict = front_matter.get("verdict").copied().ok_or("missing verdict field")?;

    assert!(
        matches!(verdict, "Go" | "GoWithCaveat" | "NoGo"),
        "expected verdict to be Go, GoWithCaveat, or NoGo, got {verdict}"
    );

    let (statement, witness) = sample_statement_and_witness();
    let adapter = CycloNizkAdapter;
    let mut rng = ChaCha8Rng::seed_from_u64(7);

    let prove_start = Instant::now();
    let proof = adapter.prove(&statement, &witness, &mut rng)?;
    let prove_ms = prove_start.elapsed().as_millis();

    let verify_start = Instant::now();
    adapter.verify(&statement, &proof)?;
    let verify_ms = verify_start.elapsed().as_millis();

    eprintln!("toy_prove_ms={prove_ms} toy_verify_ms={verify_ms}");

    assert!(prove_ms > 0, "expected prove_ms to be positive");

    Ok(())
}
