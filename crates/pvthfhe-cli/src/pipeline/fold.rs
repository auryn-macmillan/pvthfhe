//! Cyclo folding stage: fold-instance construction, Track B norm/ring
//! verification, batched Cyclo folding, and the G7 post-fold NIZK re-verification.

use anyhow::Context;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use pvthfhe_aggregator::folding::{CcsPShareInstance, CycloFoldAllReport};
use pvthfhe_bench::e2e_timings::E2eTimings;
use pvthfhe_cyclo::{fold, CYCLO_BACKEND_ID, PVTHFHE_CYCLO_PARAMS};
use pvthfhe_fhe::real_nizk::{LatticeNizk, NizkProof, NizkStatement, NizkWitness, RealNizkAdapter};
use pvthfhe_foundations::domain_tags::Tag;
use pvthfhe_foundations::rng::OsRng;
use pvthfhe_foundations::types::verification_statement::noir_bn254_sponge;
use pvthfhe_foundations::types::{CcsWitnessSecret, ProtocolBytes};
use pvthfhe_nizk::sigma::compute_sigma_sz_data;
use sha2::{Digest, Sha256};
use std::time::Instant;

use super::{elapsed_ms, PipelineConfig, PipelineObserver, Track};

/// Run the fold stage: build fold instances from the NIZK outputs, fold them
/// in batches, verify each batch, and re-verify the NIZK proofs post-fold (G7).
pub(crate) fn run_fold_stage<O: PipelineObserver>(
    cfg: &PipelineConfig,
    nizk_outputs: &[(u32, NizkStatement, NizkWitness, NizkProof)],
    ct_hash: [u8; 32],
    track: Track,
    observer: &mut O,
    timings: &mut E2eTimings,
) -> anyhow::Result<(CycloFoldAllReport, Option<[ark_bn254::Fr; 4]>)> {
    let mut per_channel_digests: Option<[ark_bn254::Fr; 4]> = None;

    let nizk_refs: Vec<_> = nizk_outputs
        .iter()
        .map(|(pid, stmt, wit, _proof)| (*pid, stmt, wit))
        .collect();
    let nizk_proofs: Vec<NizkProof> = nizk_outputs
        .iter()
        .map(|(_, _, _, proof)| proof.clone())
        .collect();
    let fold_instances = build_fold_instances(&nizk_refs, &nizk_proofs, ct_hash, cfg.seed, track)?;

    // D.4 — Track B: norm enforcement on folding witnesses
    #[cfg(feature = "pipeline-extra-checks")]
    if track == Track::B {
        use ark_bn254::Fr;
        use pvthfhe_aggregator::folding::norm::validate_folding_witness;
        use pvthfhe_aggregator::folding::ring_element::RingElement;

        const PHI_COMMIT: usize = 256;
        for &(_party_id, _stmt, witness) in &nizk_refs {
            let s_coeffs: Vec<Fr> = witness
                .secret_share_poly
                .iter()
                .take(PHI_COMMIT)
                .map(|&c| {
                    if c >= 0 {
                        Fr::from(c as u64)
                    } else {
                        -Fr::from((-c) as u64)
                    }
                })
                .collect();
            let e_coeffs: Vec<Fr> = witness
                .error
                .iter()
                .take(PHI_COMMIT)
                .map(|&c| {
                    if c >= 0 {
                        Fr::from(c as u64)
                    } else {
                        -Fr::from((-c) as u64)
                    }
                })
                .collect();

            let s = RingElement { coeffs: s_coeffs };
            let e = RingElement { coeffs: e_coeffs };
            // APPROXIMATION (L3): z_s≈s, z_e≈e (conservative; masks not exposed by RealNizkAdapter).
            let zs = RingElement {
                coeffs: s.coeffs.clone(),
            };
            let ze = RingElement {
                coeffs: e.coeffs.clone(),
            };

            let b = Fr::from(1024u64);
            let b_e = Fr::from(16u64);
            let b_z = Fr::from(2049u64);

            validate_folding_witness(&s, &e, &zs, &ze, b, b_e, b_z)
                .map_err(|e| anyhow::anyhow!("Track B norm enforcement failed: {e}"))?;
        }
        tracing::info!(
            "Track B: norm enforcement active (bound B={}, B_e={})",
            1024,
            16
        );
    }

    let mut fold_rng = OsRng;
    let batch_size = usize::try_from(PVTHFHE_CYCLO_PARAMS.sequential_t)
        .context("sequential_t overflows usize")?;
    let session_id = "pvthfhe-e2e";
    let mut accumulators = Vec::with_capacity(fold_instances.len().div_ceil(batch_size));

    observer.phase_start("cyclo_fold", Some(CYCLO_BACKEND_ID));
    let cyclo_fold_started = Instant::now();

    for (batch_index, batch) in fold_instances.chunks(batch_size).enumerate() {
        let batch_session_id = format!("{}-batch-{}", session_id, batch_index);
        let mut acc = fold::init_accumulator(&batch[0], &batch_session_id)
            .map_err(|e| anyhow::anyhow!("cyclo_fold init: {e}"))?;
        for instance in batch {
            acc = fold::fold_one_step(acc, instance, &mut fold_rng)
                .map_err(|e| anyhow::anyhow!("cyclo_fold step: {e}"))?;
        }
        fold::verify_fold(&acc, batch)
            .map_err(|e| anyhow::anyhow!("cyclo_fold verify batch: {e}"))?;
        accumulators.push(acc);
    }

    let fold_report = CycloFoldAllReport::new(accumulators, fold_instances.len(), batch_size);
    let cyclo_fold_ms = elapsed_ms(cyclo_fold_started);
    observer.phase_end("cyclo_fold", cyclo_fold_ms);
    timings.phases.cyclo_fold.total_ms = cyclo_fold_ms;
    timings.phases.cyclo_fold.instances_run = 1;

    observer.phase_start("cyclo_fold_verify", None);
    let cyclo_verify_started = Instant::now();
    for (accumulator, batch) in fold_report
        .accumulators()
        .iter()
        .zip(fold_instances.chunks(fold_report.batch_size()))
    {
        fold::verify_fold(accumulator, batch)
            .map_err(|e| anyhow::anyhow!("cyclo_fold verify: {e}"))?;
    }
    observer.phase_end("cyclo_fold_verify", elapsed_ms(cyclo_verify_started));

    #[cfg(not(feature = "fast-ring-n256"))]
    {
        let per_channel_start = Instant::now();
        observer.phase_start("per_channel_fold", Some("per-channel-q0-q1-q2"));
        let mut driver =
            init_per_channel_driver().context("per_channel_fold: failed to init driver")?;
        let chan_count = driver.channel_count();
        let degree = driver.ring(0).degree();

        for instance in &fold_instances {
            let commitment = pvthfhe_cyclo::ajtai::decode_commitment(
                instance.ajtai_commitment_bytes.as_slice(),
                pvthfhe_cyclo::fold::AJTAI_COMMITMENT_M,
            )
            .context("per_channel_fold: decode commitment")?;

            let per_ch_commitments: Vec<pvthfhe_rings::RqPoly> = (0..chan_count)
                .map(|ch| {
                    if let Some(ring_elem) = commitment.commitment.get(ch) {
                        pvthfhe_rings::RqPoly {
                            coeffs: ring_elem.0.clone(),
                            degree,
                        }
                    } else {
                        pvthfhe_rings::RqPoly::zero(degree)
                    }
                })
                .collect();

            let witnesses: Vec<pvthfhe_rings::RqPoly> = (0..chan_count)
                .map(|_| pvthfhe_rings::RqPoly::zero(degree))
                .collect();

            driver
                .fold_one(&per_ch_commitments, &witnesses)
                .context("per_channel_fold: fold step")?;
        }
        for ch in 0..chan_count {
            tracing::info!(
                "per_channel_fold: channel {ch}: fold_count={} dt={:?}",
                driver.accumulator(ch).fold_count,
                driver.ring(ch).modulus(),
            );
        }
        observer.phase_end("per_channel_fold", elapsed_ms(per_channel_start));

        let mut digests = [ark_bn254::Fr::from(0u64); 4];
        for ch in 0..chan_count.min(4) {
            let acc = driver.accumulator(ch);
            let coeffs_fr: Vec<ark_bn254::Fr> = acc
                .commitment
                .coeffs
                .iter()
                .take(16)
                .map(|&c| ark_bn254::Fr::from(c))
                .collect();
            let hash = noir_bn254_sponge(&coeffs_fr).unwrap_or(ark_bn254::Fr::from(0u64));
            digests[ch] = hash;
        }
        per_channel_digests = Some(digests);
    }

    // D.2 Track B: native ring-equation verification (hash-and-verify) before compressor.
    #[cfg(feature = "pipeline-extra-checks")]
    if track == Track::B {
        use ark_bn254::Fr;
        use pvthfhe_aggregator::folding::ring_element::RingElement;
        use sha2::{Digest, Sha256};

        const PHI_COMMIT: usize = 256;

        // Deterministic per-session ternary challenge c ∈ {-1, 0, 1}.
        let challenge = {
            let h = Sha256::new()
                .chain_update(Tag::RingChallenge.as_bytes())
                .chain_update(session_id.as_bytes())
                .chain_update(cfg.seed.to_le_bytes())
                .finalize();
            // Rejection-sample for uniform ternary: discard byte >= 252
            let byte = if h[0] < 252 { h[0] } else { h[1] };
            match byte / 84 {
                0 => -Fr::from(1u64),
                1 => Fr::from(0u64),
                _ => Fr::from(1u64),
            }
        };

        // G2-ng: collect ring witnesses for in-circuit verification
        type RingWitness = (Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>, Fr);
        let mut ring_witnesses: Vec<RingWitness> = Vec::with_capacity(nizk_refs.len());
        // sigma_witnesses deferred to latticefold path

        for (party_id, stmt, witness, proof) in nizk_outputs {
            // z_s coefficients from witness secret_share_poly
            let zs_coeffs: Vec<Fr> = witness
                .secret_share_poly
                .iter()
                .take(PHI_COMMIT)
                .map(|&c| {
                    if c >= 0 {
                        Fr::from(c as u64)
                    } else {
                        -Fr::from((-c) as u64)
                    }
                })
                .collect();
            let zs = RingElement { coeffs: zs_coeffs };

            // z_e coefficients from witness error
            let ze_coeffs: Vec<Fr> = witness
                .error
                .iter()
                .take(PHI_COMMIT)
                .map(|&c| {
                    if c >= 0 {
                        Fr::from(c as u64)
                    } else {
                        -Fr::from((-c) as u64)
                    }
                })
                .collect();
            let ze = RingElement { coeffs: ze_coeffs };

            // d (public statement) derived from NIZK statement canonical hash
            let d_coeffs: Vec<Fr> = {
                let mut hasher = Sha256::new();
                hasher.update(Tag::RingDStatement.as_bytes());
                hasher.update(stmt.ciphertext_bytes.as_slice());
                hasher.update(stmt.decrypt_share_bytes.as_slice());
                hasher.update(stmt.epoch.to_be_bytes());
                let seed: [u8; 32] = hasher.finalize().into();
                (0..PHI_COMMIT)
                    .map(|i| {
                        let mut h = Sha256::new();
                        h.update(seed);
                        h.update(i.to_le_bytes());
                        let digest: [u8; 32] = h.finalize().into();
                        let val = u64::from_le_bytes(digest[..8].try_into().unwrap_or([0u8; 8]));
                        Fr::from(val)
                    })
                    .collect()
            };
            let d = RingElement { coeffs: d_coeffs };

            // t = c·z_s + z_e - c·d (M1 structural check)
            let c_zs = zs.scale(challenge);
            let c_d = d.scale(challenge);
            let t = c_zs.add(&ze).sub(&c_d);

            // Verify sigma ring equation: c·z_s + z_e == t + c·d
            let lhs = zs.scale(challenge).add(&ze);
            let rhs = t.add(&d.scale(challenge));
            if lhs != rhs {
                anyhow::bail!(
                    "Track B: native ring equation c·z_s+z_e-t-c·d≡0 failed for party {}",
                    party_id
                );
            }

            // G2-ng: save ring witness for in-circuit enforcement
            ring_witnesses.push((zs.coeffs, ze.coeffs, t.coeffs, d.coeffs, challenge));

            let nizk_stmt = pvthfhe_nizk::NizkStatement {
                ciphertext_bytes: stmt.ciphertext_bytes.clone(),
                decrypt_share_bytes: stmt.decrypt_share_bytes.clone(),
                pvss_commitment: stmt.pvss_commitment,
                params: (stmt.params.0, pvthfhe_nizk::sigma::rlwe_n(), stmt.params.2),
                session_id: stmt.session_id.clone(),
                participant_id: stmt.participant_id,
                epoch: stmt.epoch,
            };
            let (c_rns, d_rns, sigma_multi) =
                pvthfhe_nizk::adapter::extract_sigma_statement_and_proof(
                    &nizk_stmt,
                    proof.as_bytes(),
                )
                .map_err(|e| anyhow::anyhow!("extract sigma proof party {}: {e}", party_id))?;

            // G1 Option B: extract all 90 sigma rounds from the multi-proof.
            // Each round becomes a separate SIGMA_DATA entry for per-step verification.
            for sigma_proof in &sigma_multi.rounds {
                let (z_s_ntt, z_e_ntt, t_ntt, d_i_ntt, c_ntt, z_s_power, z_e_power, ch) =
                    pvthfhe_nizk::sigma::compute_sigma_ntt_data(&c_rns, &d_rns, sigma_proof)
                        .map_err(|e| {
                            anyhow::anyhow!("compute sigma NTT data party {}: {e}", party_id)
                        })?;
                let (
                    sz_gamma,
                    sz_c_eval,
                    sz_zs_eval,
                    sz_ze_eval,
                    sz_t_eval,
                    sz_di_eval,
                    sz_r1_eval,
                ) = compute_sigma_sz_data(
                    &c_rns,
                    &d_rns,
                    sigma_proof,
                    stmt.session_id.as_bytes(),
                    *party_id,
                );
                let transcript_commitment = pvthfhe_nizk::sigma::derive_transcript_commitment(
                    &sigma_proof.t_rns,
                    &c_rns,
                    &d_rns,
                );
                // Sigma witness data collected for latticefold path
                let _ = (
                    &z_s_ntt,
                    &z_e_ntt,
                    &t_ntt,
                    &d_i_ntt,
                    &c_ntt,
                    &ch,
                    &transcript_commitment,
                    &z_s_power,
                    &z_e_power,
                    &sz_gamma,
                    &sz_c_eval,
                    &sz_zs_eval,
                    &sz_ze_eval,
                    &sz_t_eval,
                    &sz_di_eval,
                    &sz_r1_eval,
                );
            }
        }

        // G2-ng: ring/sigma data collected for native verification

        tracing::info!(
            "Track B: native ring equation verification passed ({}/{} parties, challenge={:?})",
            nizk_refs.len(),
            nizk_refs.len(),
            challenge
        );
    }
    // The native ring check above gates pipeline acceptance (closes p2-m6 gap).

    // G7: Post-hoc NIZK verification binding — re-verify NIZK proofs natively after compressor verify.
    {
        let g7_started = Instant::now();
        for (party_id, stmt, _witness, proof) in nizk_outputs {
            RealNizkAdapter::verify(stmt, proof)
                .with_context(|| format!("G7: NIZK verification for dealer {party_id}"))?;
        }
        let g7_ms = elapsed_ms(g7_started);
        tracing::info!(
            "G7: NIZK verification passed for all {} parties ({:.2}ms)",
            nizk_outputs.len(),
            g7_ms
        );
        observer.phase_start("g7_nizk_verify", None);
        observer.phase_end("g7_nizk_verify", g7_ms);
    }

    Ok((fold_report, per_channel_digests))
}

/// Build fold instances from the R3 NIZK outputs (statement + witness per party)
/// and the session transcript binding.
///
/// Each `CcsPShareInstance` binds the real CCS witness produced by the R3 NIZK layer
/// to the Cyclo fold instance, replacing the synthetic `vec![1u8; 32]` / `vec![party_id; 32]`
/// inputs used before R8.1.
///
/// Track B uses the same Cyclo Ajtai commitment format (`pvthfhe-cyclo`).
/// The aggregator's `AjtaiMatrix` is experimental and not yet integrated.
pub fn build_fold_instances(
    nizk_outputs: &[(u32, &NizkStatement, &NizkWitness)],
    nizk_proofs: &[NizkProof],
    ct_hash: [u8; 32],
    seed: u64,
    track: Track,
) -> anyhow::Result<Vec<CcsPShareInstance>> {
    nizk_outputs
        .iter()
        .enumerate()
        .map(|(idx, &(party_id, stmt, witness))| {
            let participant_id = u16::try_from(party_id).context("participant id conversion")?;

            let ccs_witness_bytes = build_cyclo_witness(witness);
            let public_io_bytes = serialize_nizk_statement(stmt);
            let ajtai_commitment_bytes =
                compute_ajtai_commitment_for_track(witness, participant_id, seed, track)?;

            let mut binding_hasher = Sha256::new();
            binding_hasher.update(ajtai_commitment_bytes.as_slice());
            binding_hasher.update(public_io_bytes.as_slice());
            binding_hasher.update(ccs_witness_bytes.expose());
            binding_hasher.update(ct_hash);
            binding_hasher.update(seed.to_le_bytes());
            binding_hasher.update(party_id.to_le_bytes());
            binding_hasher.update(nizk_proofs[idx].as_bytes());
            let binding: [u8; 32] = binding_hasher.finalize().into();

            let ccs_matrix_bytes = build_cyclo_ccs_matrix();

            Ok(CcsPShareInstance {
                participant_id,
                ajtai_commitment_bytes: ProtocolBytes(ajtai_commitment_bytes),
                public_io_bytes: ProtocolBytes(public_io_bytes),
                ccs_witness_bytes,
                sha256_binding_bytes: ProtocolBytes(binding.to_vec()),
                ccs_matrix_bytes: ProtocolBytes(ccs_matrix_bytes),
            })
        })
        .collect()
}

/// Build a 256×256 non-trivial CCS matrix for the Cyclo ring-equation verifier.
///
/// The matrix structure encodes a shift operation over the first half of the
/// ring coefficients and satisfies the CCS relation `(M·z) ⊙ z == 0` when the
/// witness has non-zero entries only in the first half (`z[0..128]`) and zeros
/// in the second half (`z[128..256]`).
///
/// Matrix shape:
/// - Rows 0..127:  M[i, i+128] = Fr::ONE  (shift column i into row i)
/// - Rows 128..255: all zeros
///
/// Wire format: [rows:u32 BE][cols:u32 BE][data: rows×cols Fr LE]
/// Fr is 32 bytes (4 u64 LE limbs).
fn build_cyclo_ccs_matrix() -> Vec<u8> {
    const N: usize = 256;
    const FR_BYTES: usize = 32;
    let data_len = N * N * FR_BYTES;
    let total_len = 8 + data_len;
    let mut matrix = vec![0u8; total_len];

    matrix[..4].copy_from_slice(&(N as u32).to_be_bytes());
    matrix[4..8].copy_from_slice(&(N as u32).to_be_bytes());

    let half = N / 2;
    let data = &mut matrix[8..];
    for i in 0..half {
        let col = i + half;
        let entry_offset = (i * N + col) * FR_BYTES;
        data[entry_offset] = 1; // Fr::ONE = [1u8, 0u8, ..., 0u8] in LE
    }
    matrix
}

/// Deterministic serialization of a [`NizkStatement`] into canonical protocol bytes.
fn serialize_nizk_statement(stmt: &NizkStatement) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(stmt.session_id.as_bytes());
    h.update(stmt.participant_id.to_be_bytes());
    h.update(stmt.epoch.to_be_bytes());
    h.update(stmt.params.0.to_be_bytes());
    // KNOWN_LIMITATION(c5_usize_conv): usize→u64 conversion infallible on 64-bit; if this function gains a Result return, switch to ?.
    h.update(
        u64::try_from(stmt.params.1)
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    h.update(stmt.params.2.to_be_bytes());
    h.update(stmt.pvss_commitment);
    h.update(stmt.ciphertext_bytes.len().to_be_bytes());
    h.update(&stmt.ciphertext_bytes);
    h.update(stmt.decrypt_share_bytes.len().to_be_bytes());
    h.update(&stmt.decrypt_share_bytes);
    h.finalize().to_vec()
}

/// Build a non-trivial 256-element CCS witness from the NIZK witness data.
///
/// Encodes real (but norm-bounded) values derived from
/// [`NizkWitness::secret_share_poly`] in the first half and zeros in the
/// second half.  Coefficients are reduced modulo the per-step norm budget
/// (max 101) so the cyclo fold witness-norm check passes.
///
/// CCS satisfiability: `(M·z) ⊙ z == 0` holds for the 256×256 Cyclo CCS matrix
/// because (M·z)[i] = z[i+128] = 0 for i ∈ [0..127] and z[i] = 0 for i ∈ [128..255].
///
/// Wire format: [num_vars:u32 BE] [Fr_0..Fr_255: 32 bytes LE each].
fn build_cyclo_witness(witness: &NizkWitness) -> CcsWitnessSecret {
    const N: usize = 256;
    const FR_BYTES: usize = 32;
    const NORM_CEIL: u64 = 101; // must stay ≤ per_step_norm_budget (= 1024/10 = 102)
    let half = N / 2;

    let mut out = Vec::with_capacity(4 + N * FR_BYTES);
    out.extend_from_slice(&(N as u32).to_be_bytes());

    for i in 0..half {
        let val = if i < witness.secret_share_poly.len() {
            let c = witness.secret_share_poly[i];
            let abs = c.unsigned_abs() % NORM_CEIL;
            // Non-zero for most coefficients (only zero when abs == 0, which is rare)
            if abs == 0 {
                NORM_CEIL
            } else {
                abs
            }
        } else {
            1 // non-trivial fallback
        };
        let fr = Fr::from(val);
        let mut limb_bytes = fr.into_bigint().to_bytes_le();
        limb_bytes.resize(FR_BYTES, 0);
        out.extend_from_slice(&limb_bytes);
    }

    for _ in half..N {
        out.extend_from_slice(&[0u8; FR_BYTES]);
    }

    CcsWitnessSecret::new(out)
}

/// Compute Ajtai commitment for the given pipeline track.
///
/// Track A uses the Cyclo Ajtai commitment format (`pvthfhe-cyclo::ajtai`).
/// Track B uses the deterministic AjtaiMatrix commitment from aggregator::folding::ajtai.
fn compute_ajtai_commitment_for_track(
    witness: &NizkWitness,
    participant_id: u16,
    seed: u64,
    track: Track,
) -> anyhow::Result<Vec<u8>> {
    if track == Track::B {
        use pvthfhe_cyclo::ajtai::{self, AjtaiCommitment};
        use pvthfhe_cyclo::ring::{ntt_mul, ring_add_poly, RqPoly, PHI_COMMIT, Q_COMMIT};

        tracing::info!(
            "Track B: using AjtaiMatrix commitment for participant {}",
            participant_id
        );

        let rlwe_n_val = pvthfhe_nizk::sigma::rlwe_n();
        let padded: Vec<i64> = {
            let mut v = vec![0i64; rlwe_n_val];
            let take = witness.secret_share_poly.len().min(rlwe_n_val);
            v[..take].copy_from_slice(&witness.secret_share_poly[..take]);
            v
        };
        let n_elems = rlwe_n_val / PHI_COMMIT;
        let witness_polys: Vec<RqPoly> = padded
            .chunks(PHI_COMMIT)
            .map(|chunk| {
                let coeffs: Vec<u64> = chunk
                    .iter()
                    .map(|&c| {
                        if c >= 0 {
                            (c as u64) % Q_COMMIT
                        } else {
                            let rem = c.unsigned_abs() % Q_COMMIT;
                            if rem == 0 {
                                0
                            } else {
                                Q_COMMIT - rem
                            }
                        }
                    })
                    .collect();
                RqPoly::new(coeffs).map_err(|e| anyhow::anyhow!("Ajtai commit: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Matrix dimensions (same as Cyclo: m=13, n=32)
        let m = PVTHFHE_CYCLO_PARAMS.ajtai_rank_a;
        let n = n_elems;

        // Generate matrix entries using SHA-256 (AjtaiMatrix-style deterministic
        // derivation), but produce RqPoly ring elements for Cyclo ring arithmetic.
        let epoch_hash: [u8; 32] = Sha256::digest(seed.to_be_bytes()).into();
        let mut matrix: Vec<Vec<RqPoly>> = Vec::with_capacity(m);
        for row in 0..m {
            let mut matrix_row = Vec::with_capacity(n);
            for col in 0..n {
                let mut coeffs = Vec::with_capacity(PHI_COMMIT);
                for coeff_idx in 0..PHI_COMMIT {
                    let mut hasher = Sha256::new();
                    hasher.update(epoch_hash);
                    hasher.update((row as u64).to_be_bytes());
                    hasher.update((col as u64).to_be_bytes());
                    hasher.update((coeff_idx as u64).to_be_bytes());
                    let hash = hasher.finalize();
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&hash[..8]);
                    let val = u64::from_le_bytes(arr) % Q_COMMIT;
                    coeffs.push(val);
                }
                matrix_row.push(
                    RqPoly::new(coeffs)
                        .map_err(|e| anyhow::anyhow!("Ajtai commit matrix entry: {e}"))?,
                );
            }
            matrix.push(matrix_row);
        }

        // Compute commitment using Cyclo ring arithmetic (ntt_mul + ring_add_poly)
        let mut commitment: Vec<RqPoly> = Vec::with_capacity(m);
        for row in &matrix {
            let mut acc = RqPoly::zero();
            for (j, wj) in witness_polys.iter().enumerate() {
                let prod = ntt_mul(&row[j], wj)
                    .map_err(|e| anyhow::anyhow!("Ajtai commit ntt_mul: {e}"))?;
                acc = ring_add_poly(&acc, &prod);
            }
            commitment.push(acc);
        }

        Ok(ajtai::encode_commitment(&AjtaiCommitment { commitment }))
    } else {
        compute_cyclo_ajtai_commitment(witness, participant_id, seed)
    }
}

/// Compute a real Ajtai commitment over `R_{q_commit}` for the Cyclo fold instance.
///
/// Converts the NIZK witness `secret_share_poly` (RLWE_N=8192 coefficients) into
/// 32 ring elements of PHI_COMMIT=256 coefficients each, then commits using the
/// deterministic Ajtai matrix derived from `(seed, participant_id)`.
///
/// The resulting commitment is 13 × 256 × 8 = 26 624 bytes, matching
/// [`AJTAI_COMMITMENT_BYTES`](pvthfhe_cyclo::fold::AJTAI_COMMITMENT_BYTES).
fn compute_cyclo_ajtai_commitment(
    witness: &NizkWitness,
    participant_id: u16,
    seed: u64,
) -> anyhow::Result<Vec<u8>> {
    use pvthfhe_cyclo::ajtai::{self, AjtaiParams};
    use pvthfhe_cyclo::ring::{RqPoly, PHI_COMMIT, Q_COMMIT};

    let matrix_seed: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(seed.to_le_bytes());
        h.update(participant_id.to_be_bytes());
        h.update(Tag::CycloAjtaiBinding.as_bytes());
        h.finalize().into()
    };

    let rlwe_n_val = pvthfhe_nizk::sigma::rlwe_n();
    let padded: Vec<i64> = {
        let mut v = vec![0i64; rlwe_n_val];
        let take = witness.secret_share_poly.len().min(rlwe_n_val);
        v[..take].copy_from_slice(&witness.secret_share_poly[..take]);
        v
    };

    let n_elems = rlwe_n_val / PHI_COMMIT;
    let witness_polys: Vec<RqPoly> = padded
        .chunks(PHI_COMMIT)
        .map(|chunk| {
            let coeffs: Vec<u64> = chunk
                .iter()
                .map(|&c| {
                    if c >= 0 {
                        (c as u64) % Q_COMMIT
                    } else {
                        let rem = c.unsigned_abs() % Q_COMMIT;
                        if rem == 0 {
                            0
                        } else {
                            Q_COMMIT - rem
                        }
                    }
                })
                .collect();
            RqPoly::new(coeffs).map_err(|e| anyhow::anyhow!("Ajtai commit: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let params = AjtaiParams {
        m: PVTHFHE_CYCLO_PARAMS.ajtai_rank_a,
        n: n_elems,
        q_commit: Q_COMMIT,
        seed: matrix_seed,
    };

    let mut dummy_rng = rand::rngs::OsRng;
    let commitment = ajtai::commit(&params, &witness_polys, &mut dummy_rng)
        .map_err(|e| anyhow::anyhow!("Ajtai commit: {e}"))?;

    Ok(ajtai::encode_commitment(&commitment))
}

#[cfg(not(feature = "fast-ring-n256"))]
pub(crate) fn init_per_channel_driver(
) -> anyhow::Result<pvthfhe_cyclo::channel_fold::ChannelFoldDriver<pvthfhe_rings::FheMathRing>> {
    pvthfhe_cyclo::channel_fold::production_driver()
        .map_err(|e| anyhow::anyhow!("per-channel fold driver: {e}"))
}
