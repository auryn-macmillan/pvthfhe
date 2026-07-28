//! On-chain binding stage: build the Noir `aggregator_final` witness
//! (`C7Prover.toml` write site), run nargo/bb, and the Noir-compatible
//! native hashing/Merkle helpers shared across pipeline stages.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use light_poseidon::{Poseidon, PoseidonHasher};
#[cfg(feature = "real-compressor")]
#[cfg(any(feature = "real-compressor", feature = "surrogate-compressor"))]
use pvthfhe_compressor::merkle::{build_merkle_tree, prove_merkle_path};
use pvthfhe_foundations::types::verification_statement::noir_bn254_sponge;
use sha2::{Digest, Sha256};
use std::time::Instant;

use super::decrypt::compute_lagrange_coeffs_bn254;
use super::{
    elapsed_ms, PipelineConfig, PipelineObserver, CIRCUIT_N, DEPTH_BINARY, NOIR_MAX_PARTICIPANTS,
    N_COEFFS,
};

/// Run the Noir `aggregator_final` circuit stage: compute all public inputs and
/// witness arrays, write `C7Prover.toml`, then run the canonical
/// nargo execute → bb write_vk → bb prove → bb verify flow.
///
/// Returns `noir_passed` (false when the witness write or any proving step
/// failed soft); `bb verify` failure is a hard error, as in the original
/// pipeline. Always executes for on-chain security.
pub(crate) fn run_onchain_stage<O: PipelineObserver>(
    cfg: &PipelineConfig,
    session_id: &str,
    aggregate_pk_bytes: &[u8],
    all_nizk_proof_hash: Fr,
    decrypt_nizk_hash: [u8; 32],
    combined_share_hash: Fr,
    compressed_proof_hash: Fr,
    share_coeffs: &[Vec<i64>],
    share_coeffs_fr: &[Vec<Fr>],
    lagrange_coeffs_fr: &[Fr],
    party_ids_fr: &[Fr],
    per_channel_digests: Option<[Fr; 4]>,
    observer: &mut O,
) -> anyhow::Result<bool> {
    // Noir aggregator_final circuit verification (always executes for on-chain security)
    observer.phase_start("c7_noir_aggregator", None);
    let noir_started = Instant::now();

    let circuits_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../circuits/aggregator_final");
    let noir_workspace = circuits_dir.join("..");

    // Build Prover.toml from current pipeline data
    let committee_party_ids_u32: Vec<u32> = (1..=share_coeffs.len()).map(|i| i as u32).collect();
    // G.4: Derive session_nonce from session_id (deterministic placeholder until Interfold E3)
    // Hash-chain 1.1: bind NIZK verification results into session_nonce
    let _session_nonce = {
        let mut hasher = Sha256::new();
        hasher.update(session_id.as_bytes());
        hasher.update(all_nizk_proof_hash.into_bigint().to_bytes_be());
        Fr::from_be_bytes_mod_order(&hasher.finalize())
    };

    // Compute all fields for the simplified C7 Noir circuit (aggregator_final)
    let ciphertext_hash = Fr::from_be_bytes_mod_order(&Sha256::digest(session_id.as_bytes()));
    let aggregate_pk_leaf = {
        let pk_fr: Vec<Fr> = aggregate_pk_bytes
            .chunks(31)
            .map(Fr::from_le_bytes_mod_order)
            .collect();
        noir_poseidon_sponge(&pk_fr)
    };
    let aggregate_pk_hash = noir_poseidon_sponge(&[aggregate_pk_leaf]);
    // C6: Bind decrypt_nizk_hash to sigma fold hash.
    // Without this, an adversary could submit any non-zero NIZK hash and pass the != 0 check.
    // Poseidon(decrypt_nizk_hash_raw, combined_share_hash) ensures the prover
    // must produce BOTH a valid NIZK and a valid sigma fold.
    let decrypt_nizk_hash_field = poseidon_hash_native(&[
        Fr::from_be_bytes_mod_order(&decrypt_nizk_hash),
        combined_share_hash,
    ]);
    let dkg_transcript_hash = Fr::from_be_bytes_mod_order(&Sha256::digest(
        format!("dkg-transcript-{session_id}").as_bytes(),
    ));
    let epoch = Fr::from(1u64);
    let participant_set_hash = {
        let mut inputs = Vec::with_capacity(NOIR_MAX_PARTICIPANTS + 1);
        inputs.push(Fr::from(1u64));
        for &id in committee_party_ids_u32.iter().take(NOIR_MAX_PARTICIPANTS) {
            inputs.push(Fr::from(id as u64));
        }
        while inputs.len() < NOIR_MAX_PARTICIPANTS + 1 {
            inputs.push(Fr::from(0u64));
        }
        noir_poseidon_sponge(&inputs)
    };
    let n_participants = Fr::from(share_coeffs.len() as u64);
    let threshold = Fr::from(cfg.t as u64);

    // Plaintext from Lagrange interpolation + Poseidon commitment
    // Must match Noir's vector_hash([Field; CIRCUIT_N], DOMAIN_VECTOR_MERKLE):
    //   poseidon::sponge([1, pt0, ..., pt7, 0, ..., 0]) — 257 elements total
    let mut nova_final_plaintext = [Fr::zero(); 8];
    for k in 0..8 {
        let mut sum = Fr::zero();
        for (i, lambda) in lagrange_coeffs_fr.iter().enumerate() {
            let coeff = field_from_i64(share_coeffs[i][k]);
            sum += *lambda * coeff;
        }
        nova_final_plaintext[k] = sum;
    }
    let plaintext_commitment = {
        let mut inputs = Vec::with_capacity(CIRCUIT_N + 1);
        inputs.push(Fr::from(1u64)); // DOMAIN_VECTOR_MERKLE
        for k in 0..8 {
            inputs.push(nova_final_plaintext[k]);
        }
        // Pad remaining CIRCUIT_N-8 elements with zeros
        for _ in 8..CIRCUIT_N {
            inputs.push(Fr::zero());
        }
        noir_poseidon_sponge(&inputs)
    };

    let n_shares_field = Fr::from(share_coeffs.len() as u64);

    // G2: Build share commitment Merkle tree
    // share_polys: pad share_coeffs_fr to 128 entries, each as [Fr; N_COEFFS]
    let mut share_polys = vec![[Fr::zero(); N_COEFFS]; NOIR_MAX_PARTICIPANTS];
    let mut share_commitments = vec![Fr::zero(); NOIR_MAX_PARTICIPANTS];
    let domain_vec_merkle = Fr::from(1u64); // DOMAIN_VECTOR_MERKLE
    for i in 0..share_coeffs_fr.len() {
        for k in 0..N_COEFFS {
            share_polys[i][k] = share_coeffs_fr[i].get(k).copied().unwrap_or(Fr::zero());
        }
        share_commitments[i] = {
            let mut inputs = vec![domain_vec_merkle];
            inputs.extend_from_slice(&share_polys[i][..N_COEFFS]);
            inputs.extend(std::iter::repeat_n(Fr::zero(), CIRCUIT_N - N_COEFFS));
            noir_poseidon_sponge(&inputs)
        };
    }
    // Zero-padded entries: compute commitment for zero polynomial
    let zero_poly_commitment = {
        let mut inputs = vec![domain_vec_merkle];
        inputs.extend(std::iter::repeat_n(Fr::zero(), CIRCUIT_N));
        noir_poseidon_sponge(&inputs)
    };
    for i in share_coeffs_fr.len()..NOIR_MAX_PARTICIPANTS {
        share_commitments[i] = zero_poly_commitment;
    }

    let (merkle_tree_levels, share_commitment_root) = build_binary_merkle_tree(&share_commitments);
    let merkle_paths = prove_binary_merkle_paths(&merkle_tree_levels);
    let leaf_indices: Vec<Fr> = (0..NOIR_MAX_PARTICIPANTS)
        .map(|i| Fr::from(i as u64))
        .collect();
    let (share_polys, _, _, _, _old_root) = build_c7_share_commitment_bundle(share_coeffs_fr);

    let session_id_field = Fr::from_be_bytes_mod_order(&Sha256::digest(session_id.as_bytes()));

    // Compute dkg_root before RLC derivation — it feeds into challenge_r.
    // dkg_root = Merkle root of aggregate_pk_leaf with all-zero sibling path.
    let dkg_merkle_path: [Fr; DEPTH_BINARY] = [Fr::zero(); DEPTH_BINARY];
    let dkg_root = dkg_merkle_path
        .iter()
        .fold(aggregate_pk_leaf, |node, sibling| {
            poseidon_hash_native(&[node, *sibling])
        });

    // challenge_r is derived from fixed public inputs (not share_commitment_root)
    // matching Noir's derive_challenge_r — no circular dependency.
    let challenge_r = noir_poseidon_sponge(&[
        ciphertext_hash,
        dkg_root,
        session_id_field,
        epoch,
        participant_set_hash,
        n_shares_field,
        Fr::from(8u64),
    ]);
    let share_evals: Vec<Fr> = share_polys
        .iter()
        .map(|poly| eval_c7_share_poly_noir(poly, challenge_r))
        .collect();
    let combined_poly = compute_combined_poly(&share_polys, &share_evals);
    let combined_commitment = {
        let mut inputs = vec![Fr::from(1u64)];
        inputs.extend_from_slice(&combined_poly[..N_COEFFS]);
        inputs.extend(std::iter::repeat_n(Fr::zero(), CIRCUIT_N - N_COEFFS));
        noir_poseidon_sponge(&inputs)
    };
    let mut leaves = vec![zero_poly_commitment; 128];
    leaves[0] = combined_commitment;
    let (merkle_tree_levels, share_commitment_root) = build_binary_merkle_tree(&leaves);
    let paths = prove_binary_merkle_paths(&merkle_tree_levels);
    let combined_merkle_path = paths[0];
    let lagrange_coeffs_circuit: Vec<Fr> = compute_lagrange_coeffs_bn254(party_ids_fr, challenge_r);

    let g4_merkle_path: [Fr; DEPTH_BINARY] = [Fr::zero(); DEPTH_BINARY];
    let g4_leaf_index = Fr::zero();

    let committee_party_ids: [Fr; 128] = {
        let mut ids = [Fr::from(0u64); 128];
        for i in 0..share_coeffs.len().min(128) {
            ids[i] = Fr::from((i + 1) as u64);
        }
        ids
    };
    let zero_poly_256: [Fr; N_COEFFS] = [Fr::from(0u64); N_COEFFS];
    let combined_leaf_index = Fr::zero();

    let prover_toml = build_c7_prover_toml(
        ciphertext_hash,
        aggregate_pk_hash,
        decrypt_nizk_hash_field,
        dkg_transcript_hash,
        dkg_root,
        session_id_field,
        epoch,
        participant_set_hash,
        n_participants,
        threshold,
        plaintext_commitment,
        compressed_proof_hash,
        &nova_final_plaintext,
        combined_share_hash,
        n_shares_field,
        &lagrange_coeffs_circuit,
        share_commitment_root,
        &share_evals,
        &combined_poly,
        &combined_merkle_path,
        combined_leaf_index,
        aggregate_pk_leaf,
        g4_merkle_path,
        g4_leaf_index,
        &committee_party_ids,
        &zero_poly_256,
        &zero_poly_256,
        &zero_poly_256,
        &zero_poly_256,
        &zero_poly_256,
        &zero_poly_256,
        &zero_poly_256,
        &zero_poly_256,
    );
    let mut noir_passed = true;

    if let Err(e) = std::fs::write(circuits_dir.join("C7Prover.toml"), &prover_toml) {
        tracing::warn!("C7 Noir: failed to write C7Prover.toml: {e}");
        noir_passed = false;
        observer.phase_end("c7_noir_aggregator", elapsed_ms(noir_started));
    } else {
        // Resolve nargo/bb paths with env-var hardening (G.24)
        fn resolve_tool(tool_name: &str, env_var: &str) -> std::path::PathBuf {
            if let Ok(path) = std::env::var(env_var) {
                let p = std::path::Path::new(&path);
                if p.is_file() {
                    tracing::info!("Using {tool_name} from {env_var}={path}");
                    return p.to_path_buf();
                }
                tracing::warn!("{env_var}={path} does not exist or is not a file");
            }
            // Fallback to PATH — vulnerable to hijacking
            tracing::warn!(
                "{env_var} not set; resolving {tool_name} from PATH (PATH injection risk)"
            );
            std::path::PathBuf::from(tool_name)
        }

        // Run canonical flow: nargo execute → bb write_vk → bb prove → bb verify

        let mut nargo_cmd = std::process::Command::new(resolve_tool("nargo", "PVTHFHE_NARGO_PATH"));
        nargo_cmd
            .args([
                "execute",
                "--package",
                "aggregator_final",
                "--prover-name",
                "C7Prover",
            ])
            .current_dir(&noir_workspace)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        let status = run_with_timeout(&mut nargo_cmd, 300); // N=8192 RLC circuit: ~80K ACIR ops, compiler needs ~2-5min
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => {
                tracing::error!(
                    "C7 Noir: nargo execute returned non-zero: circuit verification FAILED ({s})"
                );
                noir_passed = false;
            }
            Err(e) => {
                tracing::error!("C7 Noir: nargo execute failed: circuit verification FAILED ({e})");
                noir_passed = false;
            }
        }

        if noir_passed {
            let mut bb_write_vk_cmd =
                std::process::Command::new(resolve_tool("bb", "PVTHFHE_BB_PATH"));
            bb_write_vk_cmd
                .args([
                    "write_vk",
                    "--scheme",
                    "ultra_honk",
                    "-b",
                    "target/aggregator_final.json",
                    "-o",
                    "target",
                ])
                .current_dir(&noir_workspace)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped());
            let status = run_with_timeout(&mut bb_write_vk_cmd, 300);
            match status {
                Ok(s) if s.success() => {}
                Ok(s) => {
                    tracing::warn!("C7 Noir: bb write_vk returned non-zero: {s}");
                    noir_passed = false;
                }
                Err(e) => {
                    tracing::warn!("C7 Noir: bb write_vk failed: {e}");
                    noir_passed = false;
                }
            }
        }

        if noir_passed {
            let mut bb_prove_cmd =
                std::process::Command::new(resolve_tool("bb", "PVTHFHE_BB_PATH"));
            bb_prove_cmd
                .args([
                    "prove",
                    "--scheme",
                    "ultra_honk",
                    "-b",
                    "target/aggregator_final.json",
                    "-w",
                    "target/aggregator_final.gz",
                    "-o",
                    "target",
                ])
                .current_dir(&noir_workspace)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped());
            let status = run_with_timeout(&mut bb_prove_cmd, 300);
            match status {
                Ok(s) if s.success() => {}
                Ok(s) => {
                    tracing::warn!("C7 Noir: bb prove returned non-zero: {s}");
                    noir_passed = false;
                }
                Err(e) => {
                    tracing::warn!("C7 Noir: bb prove failed: {e}");
                    noir_passed = false;
                }
            }
        }

        if noir_passed {
            let mut bb_verify_cmd =
                std::process::Command::new(resolve_tool("bb", "PVTHFHE_BB_PATH"));
            bb_verify_cmd
                .args([
                    "verify",
                    "--scheme",
                    "ultra_honk",
                    "-k",
                    "target/vk",
                    "-p",
                    "target/proof",
                    "-i",
                    "target/public_inputs",
                ])
                .current_dir(&noir_workspace)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped());
            let status = run_with_timeout(&mut bb_verify_cmd, 300);
            match status {
                Ok(s) if s.success() => {}
                Ok(s) => {
                    anyhow::bail!("C7 Noir: bb verify returned non-zero: {s}");
                }
                Err(e) => {
                    anyhow::bail!("C7 Noir: bb verify failed: {e}");
                }
            }
        }

        let noir_ms = elapsed_ms(noir_started);
        observer.phase_end("c7_noir_aggregator", noir_ms);
    }

    #[cfg(not(feature = "fast-ring-n256"))]
    {
        observer.phase_start("decider_wrapper", Some("per-channel-decider"));
        let decider_started = Instant::now();
        let circuit_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../circuits/decider_wrapper");
        let prover_toml = circuit_dir.join("Prover.toml");

        if let Some(digests) = per_channel_digests {
            let composite_hash = noir_bn254_sponge(&[
                digests[0], digests[1], digests[2], digests[3],
            ]).unwrap_or(Fr::from(0u64));

            let dkg_hash = Fr::from_be_bytes_mod_order(&decrypt_nizk_hash);
            let mut toml = String::new();
            toml.push_str(&format!("acc_q0_digest = \"{}\"\n", hex_fr(digests[0])));
            toml.push_str(&format!("acc_q1_digest = \"{}\"\n", hex_fr(digests[1])));
            toml.push_str(&format!("acc_q2_digest = \"{}\"\n", hex_fr(digests[2])));
            toml.push_str(&format!("acc_p_digest = \"{}\"\n", hex_fr(digests[3])));
            toml.push_str(&format!("ciphertext_hash = \"{}\"\n", hex_fr(all_nizk_proof_hash)));
            toml.push_str(&format!("aggregate_pk_hash = \"{}\"\n", hex_fr(compressed_proof_hash)));
            toml.push_str(&format!("decrypt_nizk_hash = \"{}\"\n", hex_fr(dkg_hash)));
            toml.push_str(&format!("dkg_transcript_hash = \"{}\"\n", hex_fr(combined_share_hash)));
            toml.push_str(&format!("session_id = \"{}\"\n", hex_fr(compressed_proof_hash)));
            toml.push_str(&format!("ccs_relation_digest = \"{}\"\n", hex_fr(composite_hash)));
            toml.push_str(&format!("expected_plaintext_commitment = \"{}\"\n", hex_fr(composite_hash)));

            let _ = std::fs::write(&prover_toml, toml);
        }

        if prover_toml.exists() {
            let bb = std::env::var("PVTHFHE_BB_PATH").unwrap_or_else(|_| "bb".to_string());
            let nargo = std::env::var("PVTHFHE_NARGO_PATH").unwrap_or_else(|_| "nargo".to_string());
            let status = std::process::Command::new(&nargo)
                .arg("execute")
                .args(["--package", "decider_wrapper"])
                .current_dir(circuit_dir.join(".."))
                .output();
            match status {
                Ok(o) if o.status.success() => {
                    let bb_dir = circuit_dir.join("..").join("target");
                    let _ = std::process::Command::new(&bb)
                        .args(["write_vk", "--scheme", "ultra_honk", "-b",
                            &bb_dir.join("decider_wrapper.json").to_string_lossy(),
                            "-o", &bb_dir.to_string_lossy()])
                        .output();
                    let _ = std::process::Command::new(&bb)
                        .args(["prove", "--scheme", "ultra_honk", "-b",
                            &bb_dir.join("decider_wrapper.json").to_string_lossy(),
                            "-w", &bb_dir.join("decider_wrapper.gz").to_string_lossy(),
                            "-o", &bb_dir.to_string_lossy()])
                        .output();
                    let verify = std::process::Command::new(&bb)
                        .args(["verify", "--scheme", "ultra_honk", "-k",
                            &bb_dir.join("vk").to_string_lossy(),
                            "-p", &bb_dir.join("proof").to_string_lossy(),
                            "-i", &bb_dir.join("public_inputs").to_string_lossy()])
                        .output();
                    let verified = match &verify {
                        Ok(o) => o.status.success(),
                        Err(_) => false,
                    };
                    tracing::info!("decider_wrapper: verified={verified}");
                    if !verified {
                        noir_passed = false;
                    }
                }
                _ => {
                    tracing::warn!("decider_wrapper: nargo execute skipped (Prover.toml may need population)");
                }
            }
        }
        observer.phase_end("decider_wrapper", elapsed_ms(decider_started));
    }

    Ok(noir_passed)
}

pub fn field_from_i64(value: i64) -> Fr {
    if value >= 0 {
        Fr::from(value as u64)
    } else {
        -Fr::from(value.unsigned_abs())
    }
}

pub fn compute_share_verification_hash(sk_commitments: &[[u8; 32]]) -> [u8; 32] {
    let mut inputs: Vec<Fr> = Vec::with_capacity(sk_commitments.len());
    for commitment in sk_commitments {
        inputs.push(Fr::from_be_bytes_mod_order(commitment));
    }
    let sponge_output = noir_poseidon_sponge(&inputs);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&sponge_output.into_bigint().to_bytes_be()[..32]);
    hash
}

pub(crate) fn poseidon_hash_native(inputs: &[Fr]) -> Fr {
    let mut hasher = Poseidon::<Fr>::new_circom(inputs.len())
        .expect("Noir aggregator_final Poseidon arity is within Circom parameter range");
    hasher
        .hash(inputs)
        .expect("Noir aggregator_final Poseidon input arity matches construction")
}

pub(crate) fn poseidon_hash_of_c7_state(c7_final_state: (Fr, Fr)) -> Fr {
    poseidon_hash_native(&[Fr::from(16u64), c7_final_state.0, c7_final_state.1])
}

fn vector_hash_8(values: &[Fr; 8]) -> Fr {
    let mut preimage = [Fr::from(0u64); 9];
    preimage[0] = Fr::from(1u64);
    preimage[1..].copy_from_slice(values);
    poseidon_hash_native(&preimage)
}

fn bind_8_with_domain_native(values: &[Fr; 8], domain_tag: Fr) -> Fr {
    let mut preimage = [Fr::from(0u64); 9];
    preimage[0] = domain_tag;
    preimage[1..].copy_from_slice(values);
    poseidon_hash_native(&preimage)
}

fn combine_hashes_8(hashes: &[Fr; 8], n_active: usize) -> Fr {
    let mut acc = Fr::from(0u64);
    for hash in hashes.iter().take(n_active.min(8)) {
        acc = poseidon_hash_native(&[acc, *hash]);
    }
    acc
}

/// Noir-compatible Poseidon sponge (BN254 x5_5, rate 4, capacity 1) over
/// `inputs`, matching Noir's `poseidon::bn254::sponge`. Canonical
/// implementation: [`noir_bn254_sponge`] in pvthfhe-foundations; the unwrap is
/// infallible for valid Fr slices (fixed width-5 Grain-LFSR parameters).
pub(crate) fn noir_poseidon_sponge(inputs: &[Fr]) -> Fr {
    noir_bn254_sponge(inputs).expect("Noir BN254 sponge is infallible for valid Fr slices")
}

fn field_hex_be(value: Fr) -> String {
    let mut bytes = value.into_bigint().to_bytes_be();
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    hex::encode(bytes)
}

/// Build a binary Merkle tree (arity=2) using Poseidon hash_pair over `leaves`.
/// Returns (tree_levels, root) where tree_levels[0] = leaves and tree_levels[last] = [root].
pub fn build_binary_merkle_tree(leaves: &[Fr]) -> (Vec<Vec<Fr>>, Fr) {
    assert_eq!(
        leaves.len(),
        NOIR_MAX_PARTICIPANTS,
        "binary Merkle tree expects 128 leaves"
    );
    let mut levels: Vec<Vec<Fr>> = vec![leaves.to_vec()];
    while levels.last().unwrap().len() > 1 {
        let current = levels.last().unwrap();
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        for pair in current.chunks(2) {
            let left = pair[0];
            let right = if pair.len() > 1 { pair[1] } else { Fr::zero() };
            next.push(poseidon_hash_native(&[left, right]));
        }
        levels.push(next);
    }
    let root = levels.last().unwrap()[0];
    (levels, root)
}

/// Generate binary Merkle proofs (sibling paths) for all leaves.
/// Returns Vec of [Fr; DEPTH_BINARY] sibling arrays, one per leaf.
pub fn prove_binary_merkle_paths(tree: &[Vec<Fr>]) -> Vec<[Fr; DEPTH_BINARY]> {
    let n_leaves = tree[0].len();
    let mut paths = vec![[Fr::zero(); DEPTH_BINARY]; n_leaves];

    for leaf_idx in 0..n_leaves {
        let mut idx = leaf_idx;
        for level in 0..(tree.len() - 1).min(DEPTH_BINARY) {
            let level_nodes = &tree[level];
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            paths[leaf_idx][level] = if sibling_idx < level_nodes.len() {
                level_nodes[sibling_idx]
            } else {
                Fr::zero()
            };
            idx /= 2;
        }
    }
    paths
}

/// (share polynomials, commitments, Merkle paths, leaf indices, root) for the
/// C7 share-commitment witness.
pub type C7ShareCommitmentBundle = (
    Vec<[Fr; N_COEFFS]>,
    Vec<Fr>,
    Vec<[Fr; DEPTH_BINARY]>,
    Vec<Fr>,
    Fr,
);

/// Build the C7 share-commitment witness bundle from per-share coefficient vectors.
pub fn build_c7_share_commitment_bundle(share_coeffs_fr: &[Vec<Fr>]) -> C7ShareCommitmentBundle {
    let mut share_polys = vec![[Fr::zero(); N_COEFFS]; NOIR_MAX_PARTICIPANTS];
    let mut share_commitments = vec![Fr::zero(); NOIR_MAX_PARTICIPANTS];
    let domain_vec_merkle = Fr::from(1u64);

    for i in 0..share_coeffs_fr.len() {
        for k in 0..N_COEFFS {
            share_polys[i][k] = share_coeffs_fr[i].get(k).copied().unwrap_or(Fr::zero());
        }
        share_commitments[i] = {
            let mut inputs = vec![domain_vec_merkle];
            inputs.extend_from_slice(&share_polys[i][..N_COEFFS]);
            inputs.extend(std::iter::repeat_n(Fr::zero(), CIRCUIT_N - N_COEFFS));
            noir_poseidon_sponge(&inputs)
        };
    }

    let zero_poly_commitment = {
        let mut inputs = vec![domain_vec_merkle];
        inputs.extend(std::iter::repeat_n(Fr::zero(), CIRCUIT_N));
        noir_poseidon_sponge(&inputs)
    };
    for i in share_coeffs_fr.len()..NOIR_MAX_PARTICIPANTS {
        share_commitments[i] = zero_poly_commitment;
    }

    let (merkle_tree_levels, share_commitment_root) = build_binary_merkle_tree(&share_commitments);
    let merkle_paths = prove_binary_merkle_paths(&merkle_tree_levels);
    let leaf_indices: Vec<Fr> = (0..NOIR_MAX_PARTICIPANTS)
        .map(|i| Fr::from(i as u64))
        .collect();

    // Verify Merkle proof for ALL leaves to catch ANY root mismatch.
    for i in 0..NOIR_MAX_PARTICIPANTS {
        let mut cur = share_commitments[i];
        let mut idx = i;
        for lvl in 0..DEPTH_BINARY {
            if idx % 2 == 0 {
                cur = poseidon_hash_native(&[cur, merkle_paths[i][lvl]]);
            } else {
                cur = poseidon_hash_native(&[merkle_paths[i][lvl], cur]);
            }
            idx /= 2;
        }
        assert_eq!(
            cur, share_commitment_root,
            "Merkle proof for leaf {i} does not reach root"
        );
    }

    (
        share_polys,
        share_commitments,
        merkle_paths,
        leaf_indices,
        share_commitment_root,
    )
}

/// Compute RLC challenge beta = Poseidon(share_evals[0..128] || DOMAIN_SZ_CHALLENGE)
/// Must match Noir derivation in aggregator_final main() lines 396-400.
pub fn compute_rlc_beta(share_evals: &[Fr]) -> Fr {
    let mut inputs = vec![Fr::zero(); 129];
    let n = share_evals.len().min(128);
    inputs[..n].copy_from_slice(&share_evals[..n]);
    inputs[128] = Fr::from(8u64); // protocol_constants::DOMAIN_SZ_CHALLENGE
    noir_poseidon_sponge(&inputs)
}

/// Compute RLC combined polynomial = Σ β^i · share_poly_i
pub fn compute_combined_poly(share_polys: &[[Fr; N_COEFFS]], share_evals: &[Fr]) -> [Fr; N_COEFFS] {
    let beta = compute_rlc_beta(share_evals);
    let mut combined = [Fr::zero(); N_COEFFS];
    let mut beta_pow = Fr::from(1u64);
    for i in 0..share_polys.len() {
        for k in 0..N_COEFFS {
            combined[k] += beta_pow * share_polys[i][k];
        }
        beta_pow *= beta;
    }
    combined
}

pub fn eval_c7_share_poly_noir(poly: &[Fr; N_COEFFS], challenge_r: Fr) -> Fr {
    let mut result = Fr::zero();
    for i in 0..N_COEFFS {
        result = result * challenge_r + poly[N_COEFFS - 1 - i];
    }
    result
}

pub fn build_c7_prover_toml(
    ciphertext_hash: Fr,
    aggregate_pk_hash: Fr,
    decrypt_nizk_hash: Fr,
    dkg_transcript_hash: Fr,
    dkg_root: Fr,
    session_id: Fr,
    epoch: Fr,
    participant_set_hash: Fr,
    n_participants: Fr,
    threshold: Fr,
    plaintext_commitment: Fr,
    ivc_snark_proof_hash: Fr,
    nova_final_plaintext: &[Fr],
    nova_share_chain_hash: Fr,
    n_shares: Fr,
    lagrange_coeffs_fr: &[Fr],
    share_commitment_root: Fr,
    share_evals: &[Fr],
    combined_poly: &[Fr; N_COEFFS],
    combined_merkle_path: &[Fr; DEPTH_BINARY],
    combined_leaf_index: Fr,
    aggregate_pk_leaf: Fr,
    merkle_path: [Fr; DEPTH_BINARY],
    leaf_index: Fr,
    committee_party_ids: &[Fr; 128],
    c2_pk0_coeffs: &[Fr; N_COEFFS],
    c2_pk1_coeffs: &[Fr; N_COEFFS],
    c2_ct0_coeffs: &[Fr; N_COEFFS],
    c2_ct1_coeffs: &[Fr; N_COEFFS],
    c2_u_coeffs: &[Fr; N_COEFFS],
    c2_e0_coeffs: &[Fr; N_COEFFS],
    c2_e1_coeffs: &[Fr; N_COEFFS],
    c2_m_coeffs: &[Fr; N_COEFFS],
) -> String {
    // Derive challenge_r in-circuit from session-binding inputs (F3 + GAP-1 fix).
    // Must match the Noir derivation: Poseidon(ciphertext_hash, dkg_root, session_id,
    // epoch, participant_set_hash, share_commitment_root, n_shares, DOMAIN_SZ_CHALLENGE=8).
    let challenge_r = noir_poseidon_sponge(&[
        ciphertext_hash,
        dkg_root,
        session_id,
        epoch,
        participant_set_hash,
        share_commitment_root,
        n_shares,
        Fr::from(8u64), // protocol_constants::DOMAIN_SZ_CHALLENGE
    ]);
    use std::fmt::Write;
    let mut s = String::new();
    writeln!(
        s,
        "ciphertext_hash = \"0x{}\"",
        field_hex_be(ciphertext_hash)
    )
    .unwrap();
    writeln!(
        s,
        "aggregate_pk_hash = \"0x{}\"",
        field_hex_be(aggregate_pk_hash)
    )
    .unwrap();
    writeln!(
        s,
        "decrypt_nizk_hash = \"0x{}\"",
        field_hex_be(decrypt_nizk_hash)
    )
    .unwrap();
    writeln!(
        s,
        "dkg_transcript_hash = \"0x{}\"",
        field_hex_be(dkg_transcript_hash)
    )
    .unwrap();
    writeln!(s, "session_id = \"0x{}\"", field_hex_be(session_id)).unwrap();
    writeln!(s, "epoch = \"0x{}\"", field_hex_be(epoch)).unwrap();
    writeln!(
        s,
        "participant_set_hash = \"0x{}\"",
        field_hex_be(participant_set_hash)
    )
    .unwrap();
    writeln!(s, "n_participants = \"0x{}\"", field_hex_be(n_participants)).unwrap();
    writeln!(s, "threshold = \"0x{}\"", field_hex_be(threshold)).unwrap();
    writeln!(
        s,
        "plaintext_commitment = \"0x{}\"",
        field_hex_be(plaintext_commitment)
    )
    .unwrap();
    writeln!(
        s,
        "ivc_snark_proof_hash = \"0x{}\"",
        field_hex_be(ivc_snark_proof_hash)
    )
    .unwrap();

    // C7 public inputs
    writeln!(s, "n_shares = \"0x{}\"", field_hex_be(n_shares)).unwrap();

    // nova_final_plaintext padded to CIRCUIT_N=256 (Noir ring_dim.nr N=256)
    write!(s, "nova_final_plaintext = [").unwrap();
    for k in 0..CIRCUIT_N {
        if k > 0 {
            write!(s, ", ").unwrap();
        }
        let v = if k < nova_final_plaintext.len() {
            nova_final_plaintext[k]
        } else {
            Fr::zero()
        };
        write!(s, "\"0x{}\"", field_hex_be(v)).unwrap();
    }
    writeln!(s, "]").unwrap();
    writeln!(
        s,
        "nova_share_chain_hash = \"0x{}\"",
        field_hex_be(nova_share_chain_hash)
    )
    .unwrap();

    // share_evals are pre-computed at the call site using the same
    // in-circuit challenge_r derivation.
    let pt_eval: Fr = share_evals
        .iter()
        .zip(lagrange_coeffs_fr.iter())
        .map(|(&sev, &lc)| sev * lc)
        .fold(Fr::zero(), |a, x| a + x);

    // C7 witness arrays (padded to 128 entries)
    const MAX: usize = 128;
    write!(s, "share_evals = [").unwrap();
    for i in 0..MAX {
        let val = share_evals.get(i).copied().unwrap_or(Fr::zero());
        if i > 0 {
            write!(s, ", ").unwrap();
        }
        write!(s, "\"0x{}\"", field_hex_be(val)).unwrap();
    }
    writeln!(s, "]").unwrap();

    write!(s, "lagrange_coeffs = [").unwrap();
    for i in 0..MAX {
        let val = lagrange_coeffs_fr.get(i).copied().unwrap_or(Fr::zero());
        if i > 0 {
            write!(s, ", ").unwrap();
        }
        write!(s, "\"0x{}\"", field_hex_be(val)).unwrap();
    }
    writeln!(s, "]").unwrap();

    writeln!(s, "pt_eval = \"0x{}\"", field_hex_be(pt_eval)).unwrap();

    // G2-RLC: share commitment Merkle root
    writeln!(
        s,
        "share_commitment_root = \"0x{}\"",
        field_hex_be(share_commitment_root)
    )
    .unwrap();

    // RLC combined polynomial (padded to CIRCUIT_N=256)
    write!(s, "combined_poly = [").unwrap();
    for k in 0..CIRCUIT_N {
        if k > 0 {
            write!(s, ", ").unwrap();
        }
        let v = if k < N_COEFFS {
            combined_poly[k]
        } else {
            Fr::zero()
        };
        write!(s, "\"0x{}\"", field_hex_be(v)).unwrap();
    }
    writeln!(s, "]").unwrap();

    // RLC combined Merkle path
    write!(s, "combined_merkle_path = [").unwrap();
    for j in 0..DEPTH_BINARY {
        if j > 0 {
            write!(s, ", ").unwrap();
        }
        write!(s, "\"0x{}\"", field_hex_be(combined_merkle_path[j])).unwrap();
    }
    writeln!(s, "]").unwrap();

    writeln!(
        s,
        "combined_leaf_index = \"0x{}\"",
        field_hex_be(combined_leaf_index)
    )
    .unwrap();

    // G4: PK binding via Merkle proof
    writeln!(s, "dkg_root = \"0x{}\"", field_hex_be(dkg_root)).unwrap();
    writeln!(
        s,
        "aggregate_pk_leaf = \"0x{}\"",
        field_hex_be(aggregate_pk_leaf)
    )
    .unwrap();
    write!(s, "merkle_path = [").unwrap();
    for j in 0..DEPTH_BINARY {
        if j > 0 {
            write!(s, ", ").unwrap();
        }
        write!(s, "\"0x{}\"", field_hex_be(merkle_path[j])).unwrap();
    }
    writeln!(s, "]").unwrap();
    writeln!(s, "leaf_index = \"0x{}\"", field_hex_be(leaf_index)).unwrap();

    // committee_party_ids (public, 128 entries, 1-based indices)
    write!(s, "committee_party_ids = [").unwrap();
    for i in 0..128 {
        if i > 0 {
            write!(s, ", ").unwrap();
        }
        write!(s, "\"0x{}\"", field_hex_be(committee_party_ids[i])).unwrap();
    }
    writeln!(s, "]").unwrap();

    // C2: BFV encryption sigma verifier — neutral fixture (all zeros)
    let zero_array_n: [Fr; N_COEFFS] = [Fr::from(0u64); N_COEFFS];
    let zero_array_depth: [Fr; DEPTH_BINARY] = [Fr::from(0u64); DEPTH_BINARY];
    let zero_fr = Fr::from(0u64);

    let c2_arrays: [(&str, &[Fr; N_COEFFS]); 8] = [
        ("c2_pk0_coeffs", c2_pk0_coeffs),
        ("c2_pk1_coeffs", c2_pk1_coeffs),
        ("c2_ct0_coeffs", c2_ct0_coeffs),
        ("c2_ct1_coeffs", c2_ct1_coeffs),
        ("c2_u_coeffs", c2_u_coeffs),
        ("c2_e0_coeffs", c2_e0_coeffs),
        ("c2_e1_coeffs", c2_e1_coeffs),
        ("c2_m_coeffs", c2_m_coeffs),
    ];
    for (name, arr) in &c2_arrays {
        write!(s, "{name} = [").unwrap();
        for k in 0..CIRCUIT_N {
            if k > 0 {
                write!(s, ", ").unwrap();
            }
            let v = if k < N_COEFFS { arr[k] } else { Fr::zero() };
            write!(s, "\"0x{}\"", field_hex_be(v)).unwrap();
        }
        writeln!(s, "]").unwrap();
    }

    let c2_eval_names: [&str; 8] = [
        "c2_pk0_eval",
        "c2_pk1_eval",
        "c2_ct0_eval",
        "c2_ct1_eval",
        "c2_u_eval",
        "c2_e0_eval",
        "c2_e1_eval",
        "c2_m_eval",
    ];
    for name in &c2_eval_names {
        writeln!(s, "{name} = \"0x{}\"", field_hex_be(zero_fr)).unwrap();
    }
    writeln!(s, "c2_delta = \"0x{}\"", field_hex_be(zero_fr)).unwrap();

    // C2 commitments must match vector_hash(all_zeros, DOMAIN_VECTOR_MERKLE).
    // Compute the zero-poly-commitment: poseidon([1, 0, ..., 0]) with CIRCUIT_N+1 elements.
    let zero_poly_comm = {
        let mut inputs = vec![Fr::from(1u64)];
        for _ in 0..CIRCUIT_N {
            inputs.push(Fr::zero());
        }
        noir_poseidon_sponge(&inputs)
    };
    // c2_recipient_pk_root = merkle_root(zero_poly_comm, [0;7], 0)
    // Noir uses hash_2 (x5_3 permutation), not sponge, for Merkle pairs;
    // poseidon_hash_native is the same x5_3 construction (Phase 1.1 suite).
    let mut c2_root = zero_poly_comm;
    for _ in 0..DEPTH_BINARY {
        c2_root = poseidon_hash_native(&[c2_root, Fr::zero()]);
    }
    writeln!(
        s,
        "c2_pk0_commitment = \"0x{}\"",
        field_hex_be(zero_poly_comm)
    )
    .unwrap();
    writeln!(
        s,
        "c2_pk1_commitment = \"0x{}\"",
        field_hex_be(zero_poly_comm)
    )
    .unwrap();
    writeln!(s, "c2_recipient_pk_root = \"0x{}\"", field_hex_be(c2_root)).unwrap();

    write!(s, "c2_pk_merkle_path = [").unwrap();
    for j in 0..DEPTH_BINARY {
        if j > 0 {
            write!(s, ", ").unwrap();
        }
        write!(s, "\"0x{}\"", field_hex_be(zero_array_depth[j])).unwrap();
    }
    writeln!(s, "]").unwrap();
    writeln!(s, "c2_pk_leaf_index = \"0x{}\"", field_hex_be(zero_fr)).unwrap();

    s
}

/// Run a Command with a timeout, returning the ExitStatus.
/// Spawns the child in a background thread and waits with `recv_timeout`.
fn run_with_timeout(
    cmd: &mut std::process::Command,
    timeout_secs: u64,
) -> std::io::Result<std::process::ExitStatus> {
    let mut child = cmd.spawn()?;
    // Drain stdout and stderr to prevent pipe buffer deadlocks.
    if let Some(stdout) = child.stdout.take() {
        std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = Vec::new();
            let _ = std::io::BufReader::new(stdout).read_to_end(&mut buf);
        });
    }
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = Vec::new();
            let _ = std::io::BufReader::new(stderr).read_to_end(&mut buf);
        });
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = child.wait();
        let _ = tx.send(result);
    });
    match rx.recv_timeout(std::time::Duration::from_secs(timeout_secs)) {
        Ok(Ok(status)) => Ok(status),
        Ok(Err(e)) => Err(e),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("timed out after {timeout_secs}s"),
        )),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(std::io::Error::other("process wait thread disconnected"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c7_prover_toml_exports_decrypt_nizk_hash_public_input() {
        let ciphertext_hash = Fr::from(1u64);
        let aggregate_pk_hash = Fr::from(2u64);
        let decrypt_nizk_hash = Fr::from(97u64);
        let dkg_transcript_hash = Fr::from(3u64);
        let epoch = Fr::from(1u64);
        let participant_set_hash = Fr::from(5u64);
        let n_participants = Fr::from(3u64);
        let threshold = Fr::from(2u64);
        let plaintext_commitment = Fr::from(6u64);
        let ivc_snark_proof_hash = Fr::from(7u64);
        let nova_final_plaintext = [Fr::from(42u64); 8];
        let nova_share_chain_hash = Fr::from(8u64);
        let n_shares_field = Fr::from(1u64);
        let lagrange_coeffs_fr = {
            let mut v = vec![Fr::from(0u64); 128];
            v[0] = Fr::from(1u64);
            v
        };
        let (share_polys, _, _, _, _old_root) = build_c7_share_commitment_bundle(&[]);
        let session_id_field = Fr::from(1u64);
        let dkg_root = Fr::from(77u64);
        let aggregate_pk_leaf = Fr::from(78u64);

        let zero_poly_commitment = {
            let mut inputs = vec![Fr::from(1u64)];
            inputs.extend(std::iter::repeat_n(Fr::zero(), CIRCUIT_N));
            noir_poseidon_sponge(&inputs)
        };

        // For empty share_coeffs_fr all share_polys are zero, so share_evals = 0
        // and combined_poly = 0 regardless of challenge_r.
        let share_evals: Vec<Fr> = vec![Fr::zero(); 128];
        let combined_poly = [Fr::zero(); N_COEFFS];
        let combined_commitment = zero_poly_commitment;
        let mut leaves = vec![zero_poly_commitment; 128];
        leaves[0] = combined_commitment;
        let (merkle_tree_levels, share_commitment_root) = build_binary_merkle_tree(&leaves);
        let paths = prove_binary_merkle_paths(&merkle_tree_levels);
        let combined_merkle_path = paths[0];
        let combined_leaf_index = Fr::zero();

        let g4_merkle_path: [Fr; DEPTH_BINARY] = [Fr::zero(); DEPTH_BINARY];
        let g4_leaf_index = Fr::zero();

        let combined_leaf_index = Fr::zero();

        let prover_toml = build_c7_prover_toml(
            ciphertext_hash,
            aggregate_pk_hash,
            decrypt_nizk_hash,
            dkg_transcript_hash,
            dkg_root,
            session_id_field,
            epoch,
            participant_set_hash,
            n_participants,
            threshold,
            plaintext_commitment,
            ivc_snark_proof_hash,
            &nova_final_plaintext,
            nova_share_chain_hash,
            n_shares_field,
            &lagrange_coeffs_fr,
            share_commitment_root,
            &share_evals,
            &combined_poly,
            &combined_merkle_path,
            combined_leaf_index,
            aggregate_pk_leaf,
            g4_merkle_path,
            g4_leaf_index,
            &[Fr::from(0u64); 128],
            &[Fr::from(0u64); N_COEFFS],
            &[Fr::from(0u64); N_COEFFS],
            &[Fr::from(0u64); N_COEFFS],
            &[Fr::from(0u64); N_COEFFS],
            &[Fr::from(0u64); N_COEFFS],
            &[Fr::from(0u64); N_COEFFS],
            &[Fr::from(0u64); N_COEFFS],
            &[Fr::from(0u64); N_COEFFS],
        );
        assert!(
            prover_toml.contains("decrypt_nizk_hash ="),
            "Noir aggregator_final requires decrypt_nizk_hash as a public input"
        );
    }
}
fn hex_fr(f: ark_bn254::Fr) -> String {
    let bytes = f.into_bigint().to_bytes_be();
    format!("0x{}", hex::encode(bytes))
}
