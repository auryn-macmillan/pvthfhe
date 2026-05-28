use super::ark_to_nova_scalar;
use super::NovaScalar;
use nova_snark::frontend::gadgets::num::AllocatedNum;
use nova_snark::frontend::{ConstraintSystem, SynthesisError};

use ark_ff::BigInteger;
use ark_ff::PrimeField as ArkPrimeField;
use bp_ff::Field;

pub fn sigma_verify_step_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    step: usize,
) -> Result<AllocatedNum<NovaScalar>, SynthesisError> {
    use super::SIGMA_DATA;

    let num_rounds = super::SIGMA_REPETITIONS;
    if num_rounds == 0 {
        return AllocatedNum::alloc(cs.namespace(|| "sigma_zero"), || Ok(NovaScalar::from(0u64)));
    }

    // Check if any round has data for this step
    let has_data = (0..num_rounds).any(|r| {
        let data_idx = step * num_rounds + r;
        SIGMA_DATA.with(|cell| {
            let data = cell.inner().borrow();
            data.get(data_idx)
                .or_else(|| step.checked_sub(1).and_then(|zb| data.get(zb)))
                .is_some()
        })
    });

    if !has_data {
        return AllocatedNum::alloc(cs.namespace(|| "sigma_zero"), || Ok(NovaScalar::from(0u64)));
    }

    for round in 0..num_rounds {
        let data_idx = step * num_rounds + round;
        let witness_opt = SIGMA_DATA.with(|cell| {
            let data = cell.inner().borrow();
            data.get(data_idx)
                .or_else(|| {
                    step.checked_sub(1)
                        .and_then(|zb| data.get(zb * num_rounds + round))
                })
                .cloned()
        });

        let w = match witness_opt {
            Some(w) => w,
            None => {
                let one = AllocatedNum::alloc(
                    cs.namespace(|| format!("sigma_no_data_r{round}")),
                    || Ok(NovaScalar::from(1u64)),
                )?;
                let zero = AllocatedNum::alloc(
                    cs.namespace(|| format!("sigma_no_data_zero_r{round}")),
                    || Ok(NovaScalar::from(0u64)),
                )?;
                cs.enforce(
                    || format!("sigma_no_data_fail_r{round}"),
                    |lc| lc + CS::one(),
                    |lc| lc + one.get_variable(),
                    |lc| lc + zero.get_variable(),
                );
                continue;
            }
        };

        let commitment_binding = super::sigma_transcript_commitment_scalar(&w);
        AllocatedNum::alloc(
            cs.namespace(|| format!("sigma_t2_commitment_binding_r{round}")),
            || Ok(commitment_binding),
        )?;

        let f_ch: NovaScalar = ark_to_nova_scalar(w.ch);
        let ch_var =
            AllocatedNum::alloc(cs.namespace(|| format!("sigma_ch_r{round}")), || Ok(f_ch))?;

        for eval_idx in 0..3 {
            for limb in 0..3 {
                let idx = eval_idx * 3 + limb;

                if idx >= w.sz_c_eval.len()
                    || idx >= w.sz_zs_eval.len()
                    || idx >= w.sz_ze_eval.len()
                    || idx >= w.sz_t_eval.len()
                    || idx >= w.sz_di_eval.len()
                    || idx >= w.sz_r1_eval.len()
                {
                    let one = AllocatedNum::alloc(
                        cs.namespace(|| format!("sigma_fail_r{round}_{eval_idx}_{limb}")),
                        || Ok(NovaScalar::from(1u64)),
                    )?;
                    let zero = AllocatedNum::alloc(
                        cs.namespace(|| format!("sigma_fail_zero_r{round}_{eval_idx}_{limb}")),
                        || Ok(NovaScalar::from(0u64)),
                    )?;
                    cs.enforce(
                        || format!("sigma_bounds_fail_r{round}_{eval_idx}_{limb}"),
                        |lc| lc + CS::one(),
                        |lc| lc + one.get_variable(),
                        |lc| lc + zero.get_variable(),
                    );
                    continue;
                }

                let sz_c_eval = AllocatedNum::alloc(
                    cs.namespace(|| format!("sz_c_eval_r{round}_{eval_idx}_{limb}")),
                    || Ok(NovaScalar::from(w.sz_c_eval[idx])),
                )?;
                let sz_zs_eval = AllocatedNum::alloc(
                    cs.namespace(|| format!("sz_zs_eval_r{round}_{eval_idx}_{limb}")),
                    || Ok(NovaScalar::from(w.sz_zs_eval[idx])),
                )?;
                let sz_ze_eval = AllocatedNum::alloc(
                    cs.namespace(|| format!("sz_ze_eval_r{round}_{eval_idx}_{limb}")),
                    || Ok(NovaScalar::from(w.sz_ze_eval[idx])),
                )?;
                let sz_t_eval = AllocatedNum::alloc(
                    cs.namespace(|| format!("sz_t_eval_r{round}_{eval_idx}_{limb}")),
                    || Ok(NovaScalar::from(w.sz_t_eval[idx])),
                )?;
                let sz_di_eval = AllocatedNum::alloc(
                    cs.namespace(|| format!("sz_di_eval_r{round}_{eval_idx}_{limb}")),
                    || Ok(NovaScalar::from(w.sz_di_eval[idx])),
                )?;
                let sz_r1_eval = AllocatedNum::alloc(
                    cs.namespace(|| format!("sz_r1_eval_r{round}_{eval_idx}_{limb}")),
                    || Ok(NovaScalar::from(w.sz_r1_eval[idx])),
                )?;

                let q_const = AllocatedNum::alloc(
                    cs.namespace(|| format!("q_const_r{round}_{eval_idx}_{limb}")),
                    || Ok(NovaScalar::from(super::SIGMA_RNS_MODULI[limb])),
                )?;

                let c_mul_zs = sz_c_eval.mul(
                    cs.namespace(|| format!("c_mul_zs_r{round}_{eval_idx}_{limb}")),
                    &sz_zs_eval,
                )?;
                let lhs = c_mul_zs.add(
                    cs.namespace(|| format!("sigma_lhs_r{round}_{eval_idx}_{limb}")),
                    &sz_ze_eval,
                )?;

                let ch_mul_di = ch_var.mul(
                    cs.namespace(|| format!("ch_mul_di_r{round}_{eval_idx}_{limb}")),
                    &sz_di_eval,
                )?;
                let t_plus_chdi = sz_t_eval.add(
                    cs.namespace(|| format!("t_plus_chdi_r{round}_{eval_idx}_{limb}")),
                    &ch_mul_di,
                )?;
                let q_mul_r1 = q_const.mul(
                    cs.namespace(|| format!("q_mul_r1_r{round}_{eval_idx}_{limb}")),
                    &sz_r1_eval,
                )?;
                let rhs = t_plus_chdi.add(
                    cs.namespace(|| format!("sigma_rhs_r{round}_{eval_idx}_{limb}")),
                    &q_mul_r1,
                )?;

                cs.enforce(
                    || format!("sigma_eq_r{round}_{eval_idx}_{limb}"),
                    |lc| lc + CS::one(),
                    |lc| lc + lhs.get_variable(),
                    |lc| lc + rhs.get_variable(),
                );

                norm_range_check_bp(
                    cs,
                    &sz_r1_eval,
                    w.sz_r1_eval[idx],
                    1u64,
                    &format!("sz_r1_range_r{round}_{eval_idx}_{limb}"),
                )?;
            }
        }

        let n = super::SIGMA_VERIFY_COEFFS;
        let n_power = n.min(w.z_s_power.len()).min(w.z_e_power.len());
        if n_power > 0 {
            const B_Z_S: u64 = 131_072;
            const B_Z_E: u64 = 131_072;

            for k in 0..n_power {
                let zs_val = w.z_s_power[k].unsigned_abs();
                let ze_val = w.z_e_power[k].unsigned_abs();

                if zs_val > B_Z_S || ze_val > B_Z_E {
                    let one = AllocatedNum::alloc(
                        cs.namespace(|| format!("norm_fail_z_r{round}_{k}")),
                        || Ok(NovaScalar::from(1u64)),
                    )?;
                    let zero = AllocatedNum::alloc(
                        cs.namespace(|| format!("norm_fail_zero_r{round}_{k}")),
                        || Ok(NovaScalar::from(0u64)),
                    )?;
                    cs.enforce(
                        || format!("norm_bound_fail_r{round}_{k}"),
                        |lc| lc + CS::one(),
                        |lc| lc + one.get_variable(),
                        |lc| lc + zero.get_variable(),
                    );
                    continue;
                }

                let zs_var =
                    AllocatedNum::alloc(cs.namespace(|| format!("zs_power_r{round}_{k}")), || {
                        Ok(NovaScalar::from(zs_val))
                    })?;
                let ze_var =
                    AllocatedNum::alloc(cs.namespace(|| format!("ze_power_r{round}_{k}")), || {
                        Ok(NovaScalar::from(ze_val))
                    })?;

                norm_range_check_bp(cs, &zs_var, zs_val, B_Z_S, &format!("zs_norm_r{round}_{k}"))?;
                norm_range_check_bp(cs, &ze_var, ze_val, B_Z_E, &format!("ze_norm_r{round}_{k}"))?;
            }
        }
    }

    AllocatedNum::alloc(cs.namespace(|| "sigma_ok"), || {
        Ok(NovaScalar::from(num_rounds as u64))
    })
}

#[cfg(feature = "symphony-t4")]
pub fn sigma_verify_step_projected<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    step: usize,
) -> Result<AllocatedNum<NovaScalar>, SynthesisError> {
    use super::monomial_range::monomial_range_check_bp;
    use super::SIGMA_DATA;
    use super::SIGMA_RESPONSE_DATA;

    let has_data = SIGMA_DATA.with(|cell| {
        let data = cell.inner().borrow();
        data.get(step)
            .or_else(|| step.checked_sub(1).and_then(|zb| data.get(zb)))
            .is_some()
    });

    if !has_data {
        return AllocatedNum::alloc(cs.namespace(|| "sigma_proj_zero"), || {
            Ok(NovaScalar::from(0u64))
        });
    }

    let witness_opt = SIGMA_DATA.with(|cell| {
        let data = cell.inner().borrow();
        data.get(step)
            .or_else(|| step.checked_sub(1).and_then(|zb| data.get(zb)))
            .cloned()
    });

    let w = match witness_opt {
        Some(w) => w,
        None => {
            return AllocatedNum::alloc(cs.namespace(|| "sigma_proj_zero"), || {
                Ok(NovaScalar::from(0u64))
            });
        }
    };

    let f_ch: NovaScalar = ark_to_nova_scalar(w.ch);
    let ch_var = AllocatedNum::alloc(cs.namespace(|| "sigma_proj_ch"), || Ok(f_ch))?;

    for eval_idx in 0..3 {
        for limb in 0..3 {
            let idx = eval_idx * 3 + limb;

            if idx >= w.sz_c_eval.len()
                || idx >= w.sz_zs_eval.len()
                || idx >= w.sz_ze_eval.len()
                || idx >= w.sz_t_eval.len()
                || idx >= w.sz_di_eval.len()
                || idx >= w.sz_r1_eval.len()
            {
                let one =
                    AllocatedNum::alloc(cs.namespace(|| format!("sigma_proj_fail_{idx}")), || {
                        Ok(NovaScalar::from(1u64))
                    })?;
                let zero = AllocatedNum::alloc(
                    cs.namespace(|| format!("sigma_proj_fail_zero_{idx}")),
                    || Ok(NovaScalar::from(0u64)),
                )?;
                cs.enforce(
                    || format!("sigma_proj_bounds_fail_{idx}"),
                    |lc| lc + CS::one(),
                    |lc| lc + one.get_variable(),
                    |lc| lc + zero.get_variable(),
                );
                continue;
            }

            let sz_c_eval = AllocatedNum::alloc(
                cs.namespace(|| format!("sigma_proj_c_eval_{eval_idx}_{limb}")),
                || Ok(NovaScalar::from(w.sz_c_eval[idx])),
            )?;
            let sz_zs_eval = AllocatedNum::alloc(
                cs.namespace(|| format!("sigma_proj_zs_eval_{eval_idx}_{limb}")),
                || Ok(NovaScalar::from(w.sz_zs_eval[idx])),
            )?;
            let sz_ze_eval = AllocatedNum::alloc(
                cs.namespace(|| format!("sigma_proj_ze_eval_{eval_idx}_{limb}")),
                || Ok(NovaScalar::from(w.sz_ze_eval[idx])),
            )?;
            let sz_t_eval = AllocatedNum::alloc(
                cs.namespace(|| format!("sigma_proj_t_eval_{eval_idx}_{limb}")),
                || Ok(NovaScalar::from(w.sz_t_eval[idx])),
            )?;
            let sz_di_eval = AllocatedNum::alloc(
                cs.namespace(|| format!("sigma_proj_di_eval_{eval_idx}_{limb}")),
                || Ok(NovaScalar::from(w.sz_di_eval[idx])),
            )?;
            let sz_r1_eval = AllocatedNum::alloc(
                cs.namespace(|| format!("sigma_proj_r1_eval_{eval_idx}_{limb}")),
                || Ok(NovaScalar::from(w.sz_r1_eval[idx])),
            )?;

            let q_const = AllocatedNum::alloc(
                cs.namespace(|| format!("sigma_proj_q_const_{eval_idx}_{limb}")),
                || Ok(NovaScalar::from(super::SIGMA_RNS_MODULI[limb])),
            )?;

            let c_mul_zs = sz_c_eval.mul(
                cs.namespace(|| format!("sigma_proj_c_mul_zs_{eval_idx}_{limb}")),
                &sz_zs_eval,
            )?;
            let lhs = c_mul_zs.add(
                cs.namespace(|| format!("sigma_proj_lhs_{eval_idx}_{limb}")),
                &sz_ze_eval,
            )?;

            let ch_mul_di = ch_var.mul(
                cs.namespace(|| format!("sigma_proj_ch_mul_di_{eval_idx}_{limb}")),
                &sz_di_eval,
            )?;
            let t_plus_chdi = sz_t_eval.add(
                cs.namespace(|| format!("sigma_proj_t_plus_chdi_{eval_idx}_{limb}")),
                &ch_mul_di,
            )?;
            let q_mul_r1 = q_const.mul(
                cs.namespace(|| format!("sigma_proj_q_mul_r1_{eval_idx}_{limb}")),
                &sz_r1_eval,
            )?;
            let rhs = t_plus_chdi.add(
                cs.namespace(|| format!("sigma_proj_rhs_{eval_idx}_{limb}")),
                &q_mul_r1,
            )?;

            cs.enforce(
                || format!("sigma_proj_eq_{eval_idx}_{limb}"),
                |lc| lc + CS::one(),
                |lc| lc + lhs.get_variable(),
                |lc| lc + rhs.get_variable(),
            );

            norm_range_check_bp(
                cs,
                &sz_r1_eval,
                w.sz_r1_eval[idx],
                1u64,
                &format!("sigma_proj_sz_r1_range_{eval_idx}_{limb}"),
            )?;
        }
    }

    const T4_JL_PROJECTION_DIM: usize = 256;
    const B_Z_S: u64 = 131_072;
    const B_Z_E: u64 = 131_072;
    const PROJ_BOUND_ZS: u64 = 2_097_152;
    const PROJ_BOUND_ZE: u64 = 2_097_152;

    let (p_s_vec, p_e_vec, jl_entries) = SIGMA_RESPONSE_DATA.with(|cell| {
        let data = cell.inner().borrow();
        if let Some((_, _, ref p_s, ref p_e, ref entries)) = data.get(step) {
            (p_s.clone(), p_e.clone(), entries.clone())
        } else {
            (vec![], vec![], vec![])
        }
    });

    if !p_s_vec.is_empty() && !p_e_vec.is_empty() {
        let n = super::SIGMA_VERIFY_COEFFS;
        let n_power = n.min(w.z_s_power.len()).min(w.z_e_power.len());

        let minus_one =
            AllocatedNum::alloc(cs.namespace(|| "proj_neg_one"), || Ok(-NovaScalar::ONE))?;

        let proj_dim = T4_JL_PROJECTION_DIM
            .min(p_s_vec.len())
            .min(p_e_vec.len())
            .min(jl_entries.len());

        for k in 0..proj_dim {
            let mut raw_sum_s =
                AllocatedNum::alloc(cs.namespace(|| format!("proj_raw_s_{k}_init")), || {
                    Ok(NovaScalar::ZERO)
                })?;
            let mut raw_sum_e =
                AllocatedNum::alloc(cs.namespace(|| format!("proj_raw_e_{k}_init")), || {
                    Ok(NovaScalar::ZERO)
                })?;

            if k < jl_entries.len() {
                for &(j, sign) in &jl_entries[k] {
                    if j < n_power {
                        let zs_val = NovaScalar::from(w.z_s_power[j].unsigned_abs());
                        let ze_val = NovaScalar::from(w.z_e_power[j].unsigned_abs());
                        let zs_var = AllocatedNum::alloc(
                            cs.namespace(|| format!("proj_zs_{k}_{j}")),
                            || Ok(zs_val),
                        )?;
                        let ze_var = AllocatedNum::alloc(
                            cs.namespace(|| format!("proj_ze_{k}_{j}")),
                            || Ok(ze_val),
                        )?;

                        if sign {
                            raw_sum_s = raw_sum_s
                                .add(cs.namespace(|| format!("proj_zs_add_{k}_{j}")), &zs_var)?;
                            raw_sum_e = raw_sum_e
                                .add(cs.namespace(|| format!("proj_ze_add_{k}_{j}")), &ze_var)?;
                        } else {
                            let neg_zs = zs_var
                                .mul(cs.namespace(|| format!("proj_zs_neg_{k}_{j}")), &minus_one)?;
                            let neg_ze = ze_var
                                .mul(cs.namespace(|| format!("proj_ze_neg_{k}_{j}")), &minus_one)?;
                            raw_sum_s = raw_sum_s
                                .add(cs.namespace(|| format!("proj_zs_sub_{k}_{j}")), &neg_zs)?;
                            raw_sum_e = raw_sum_e
                                .add(cs.namespace(|| format!("proj_ze_sub_{k}_{j}")), &neg_ze)?;
                        }
                    }
                }
            }

            let expected_s_val = NovaScalar::from(p_s_vec[k].unsigned_abs());
            let expected_e_val = NovaScalar::from(p_e_vec[k].unsigned_abs());
            let expected_s =
                AllocatedNum::alloc(cs.namespace(|| format!("proj_exp_s_{k}")), || {
                    Ok(expected_s_val)
                })?;
            let expected_e =
                AllocatedNum::alloc(cs.namespace(|| format!("proj_exp_e_{k}")), || {
                    Ok(expected_e_val)
                })?;

            cs.enforce(
                || format!("proj_jl_s_{k}"),
                |lc| lc + CS::one(),
                |lc| lc + raw_sum_s.get_variable(),
                |lc| lc + expected_s.get_variable(),
            );
            cs.enforce(
                || format!("proj_jl_e_{k}"),
                |lc| lc + CS::one(),
                |lc| lc + raw_sum_e.get_variable(),
                |lc| lc + expected_e.get_variable(),
            );

            let proj_s_val = p_s_vec[k].unsigned_abs();
            let proj_e_val = p_e_vec[k].unsigned_abs();

            if proj_s_val > PROJ_BOUND_ZS || proj_e_val > PROJ_BOUND_ZE {
                let one =
                    AllocatedNum::alloc(cs.namespace(|| format!("proj_bound_fail_{k}")), || {
                        Ok(NovaScalar::ONE)
                    })?;
                let zero =
                    AllocatedNum::alloc(cs.namespace(|| format!("proj_bound_fail_z_{k}")), || {
                        Ok(NovaScalar::ZERO)
                    })?;
                cs.enforce(
                    || format!("proj_bound_fail_c_{k}"),
                    |lc| lc + CS::one(),
                    |lc| lc + one.get_variable(),
                    |lc| lc + zero.get_variable(),
                );
                continue;
            }

            let proj_s_var =
                AllocatedNum::alloc(cs.namespace(|| format!("proj_s_var_{k}")), || {
                    Ok(NovaScalar::from(proj_s_val))
                })?;
            let proj_e_var =
                AllocatedNum::alloc(cs.namespace(|| format!("proj_e_var_{k}")), || {
                    Ok(NovaScalar::from(proj_e_val))
                })?;

            monomial_range_check_bp(
                cs,
                &proj_s_var,
                proj_s_val,
                PROJ_BOUND_ZS,
                &format!("proj_zs_range_{k}"),
            )?;
            monomial_range_check_bp(
                cs,
                &proj_e_var,
                proj_e_val,
                PROJ_BOUND_ZE,
                &format!("proj_ze_range_{k}"),
            )?;
        }
    }

    AllocatedNum::alloc(cs.namespace(|| "sigma_proj_ok"), || {
        Ok(NovaScalar::from(1u64))
    })
}

pub fn ring_verify_step_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    step: usize,
) -> Result<AllocatedNum<NovaScalar>, SynthesisError> {
    use super::CYCLO_RING_DATA;

    let witness_opt = CYCLO_RING_DATA.with(|cell| {
        let ring_data = cell.inner().borrow();
        let w = ring_data
            .get(step)
            .or_else(|| step.checked_sub(1).and_then(|zb| ring_data.get(zb)));
        w.cloned()
    });

    let witness = match witness_opt {
        Some(w) => w,
        None => {
            return AllocatedNum::alloc(cs.namespace(|| "ring_zero"), || {
                Ok(NovaScalar::from(0u64))
            });
        }
    };

    let f_ch: NovaScalar = ark_to_nova_scalar(witness.challenge);
    let ch_var = AllocatedNum::alloc(cs.namespace(|| "ring_ch"), || Ok(f_ch))?;

    let n_coeffs = 256usize
        .min(witness.z_s.len())
        .min(witness.z_e.len())
        .min(witness.t.len())
        .min(witness.d.len());

    for k in 0..n_coeffs {
        let zs_k: NovaScalar = ark_to_nova_scalar(witness.z_s[k]);
        let ze_k: NovaScalar = ark_to_nova_scalar(witness.z_e[k]);
        let t_k: NovaScalar = ark_to_nova_scalar(witness.t[k]);
        let d_k: NovaScalar = ark_to_nova_scalar(witness.d[k]);

        let zs_var = AllocatedNum::alloc(cs.namespace(|| format!("ring_zs_{k}")), || Ok(zs_k))?;
        let ze_var = AllocatedNum::alloc(cs.namespace(|| format!("ring_ze_{k}")), || Ok(ze_k))?;
        let t_var = AllocatedNum::alloc(cs.namespace(|| format!("ring_t_{k}")), || Ok(t_k))?;
        let d_var = AllocatedNum::alloc(cs.namespace(|| format!("ring_d_{k}")), || Ok(d_k))?;

        let ch_mul_zs = ch_var.mul(cs.namespace(|| format!("ring_ch_mul_zs_{k}")), &zs_var)?;
        let lhs = ch_mul_zs.add(cs.namespace(|| format!("ring_lhs_{k}")), &ze_var)?;

        let ch_mul_d = ch_var.mul(cs.namespace(|| format!("ring_ch_mul_d_{k}")), &d_var)?;
        let rhs = t_var.add(cs.namespace(|| format!("ring_rhs_{k}")), &ch_mul_d)?;

        cs.enforce(
            || format!("ring_eq_{k}"),
            |lc| lc + CS::one(),
            |lc| lc + lhs.get_variable(),
            |lc| lc + rhs.get_variable(),
        );
    }

    AllocatedNum::alloc(cs.namespace(|| "ring_ok"), || Ok(NovaScalar::from(1u64)))
}

pub fn bfv_verify_step_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    step: usize,
) -> Result<AllocatedNum<NovaScalar>, SynthesisError> {
    use super::bfv_encryption_circuit;

    let has_data = bfv_encryption_circuit::BFV_ENCRYPTION_DATA.with(|cell| {
        let data = cell.borrow();
        let step_data = data
            .get(step)
            .or_else(|| step.checked_sub(1).and_then(|zb| data.get(zb)));
        step_data.is_some_and(|d| d.len() >= bfv_encryption_circuit::BFV_STEP_DATA_LEN)
    });

    if !has_data {
        return AllocatedNum::alloc(cs.namespace(|| "bfv_no_data"), || {
            Ok(NovaScalar::from(1u64))
        });
    }

    let step_data_opt = bfv_encryption_circuit::BFV_ENCRYPTION_DATA.with(|cell| {
        let data = cell.borrow();
        data.get(step)
            .or_else(|| step.checked_sub(1).and_then(|zb| data.get(zb)))
            .cloned()
    });

    let step_data = match step_data_opt {
        Some(d) if d.len() >= bfv_encryption_circuit::BFV_STEP_DATA_LEN => d,
        _ => {
            let one =
                AllocatedNum::alloc(cs.namespace(|| "bfv_fail"), || Ok(NovaScalar::from(1u64)))?;
            let zero = AllocatedNum::alloc(cs.namespace(|| "bfv_fail_zero"), || {
                Ok(NovaScalar::from(0u64))
            })?;
            cs.enforce(
                || "bfv bounds fail",
                |lc| lc + CS::one(),
                |lc| lc + one.get_variable(),
                |lc| lc + zero.get_variable(),
            );
            return AllocatedNum::alloc(cs.namespace(|| "bfv_ok"), || Ok(NovaScalar::from(1u64)));
        }
    };

    let to_s = ark_to_nova_scalar;
    let ct0_vals: Vec<NovaScalar> = step_data[0..3].iter().map(|fr| to_s(*fr)).collect();
    let ct1_vals: Vec<NovaScalar> = step_data[3..6].iter().map(|fr| to_s(*fr)).collect();
    let pk0_vals: Vec<NovaScalar> = step_data[6..9].iter().map(|fr| to_s(*fr)).collect();
    let pk1_vals: Vec<NovaScalar> = step_data[9..12].iter().map(|fr| to_s(*fr)).collect();
    let delta_vals: Vec<NovaScalar> = step_data[12..15].iter().map(|fr| to_s(*fr)).collect();
    let u_val: NovaScalar = to_s(step_data[15]);
    let e0_val: NovaScalar = to_s(step_data[16]);
    let e1_val: NovaScalar = to_s(step_data[17]);
    let m_val: NovaScalar = to_s(step_data[18]);
    let quot0_vals: Vec<NovaScalar> = step_data[19..22].iter().map(|fr| to_s(*fr)).collect();
    let quot1_vals: Vec<NovaScalar> = step_data[22..25].iter().map(|fr| to_s(*fr)).collect();
    let gamma_vals: Vec<NovaScalar> = step_data[25..28].iter().map(|fr| to_s(*fr)).collect();

    let alloc_vec = |cs: &mut CS,
                     vals: &[NovaScalar],
                     prefix: &str|
     -> Result<Vec<AllocatedNum<NovaScalar>>, SynthesisError> {
        vals.iter()
            .enumerate()
            .map(|(i, &v)| AllocatedNum::alloc(cs.namespace(|| format!("{prefix}_{i}")), || Ok(v)))
            .collect()
    };

    let ct0_vars = alloc_vec(cs, &ct0_vals, "bfv_ct0")?;
    let ct1_vars = alloc_vec(cs, &ct1_vals, "bfv_ct1")?;
    let pk0_vars = alloc_vec(cs, &pk0_vals, "bfv_pk0")?;
    let pk1_vars = alloc_vec(cs, &pk1_vals, "bfv_pk1")?;
    let delta_vars = alloc_vec(cs, &delta_vals, "bfv_delta")?;
    let quot0_vars = alloc_vec(cs, &quot0_vals, "bfv_quot0")?;
    let quot1_vars = alloc_vec(cs, &quot1_vals, "bfv_quot1")?;
    let gamma_vars = alloc_vec(cs, &gamma_vals, "bfv_gamma")?;

    let u_var = AllocatedNum::alloc(cs.namespace(|| "bfv_u"), || Ok(u_val))?;
    let e0_var = AllocatedNum::alloc(cs.namespace(|| "bfv_e0"), || Ok(e0_val))?;
    let e1_var = AllocatedNum::alloc(cs.namespace(|| "bfv_e1"), || Ok(e1_val))?;
    let m_var = AllocatedNum::alloc(cs.namespace(|| "bfv_m"), || Ok(m_val))?;

    let q_consts: Vec<AllocatedNum<NovaScalar>> = bfv_encryption_circuit::BFV_Q
        .iter()
        .enumerate()
        .map(|(i, &q)| {
            AllocatedNum::alloc(cs.namespace(|| format!("bfv_q_{i}")), || {
                Ok(NovaScalar::from(q))
            })
        })
        .collect::<Result<_, _>>()?;

    let zero_val = AllocatedNum::alloc(cs.namespace(|| "bfv_zero"), || Ok(NovaScalar::from(0u64)))?;

    // ct0 equation: Σ_l γ^l · (ct0[l] - pk0[l]·u - e0 - Δ[l]·m - q[l]·quot0[l]) == 0
    let mut acc0 = AllocatedNum::alloc(cs.namespace(|| "bfv_acc0_init"), || {
        Ok(NovaScalar::from(0u64))
    })?;

    for l in 0..bfv_encryption_circuit::BFV_L {
        let pk0_mul_u = pk0_vars[l].mul(cs.namespace(|| format!("bfv_pk0u_{l}")), &u_var)?;
        let delta_mul_m = delta_vars[l].mul(cs.namespace(|| format!("bfv_deltam_{l}")), &m_var)?;
        let q_mul_quot0 =
            q_consts[l].mul(cs.namespace(|| format!("bfv_qquot0_{l}")), &quot0_vars[l])?;

        let term = AllocatedNum::alloc(cs.namespace(|| format!("bfv_term0_{l}")), || {
            let pu = pk0_mul_u.get_value().unwrap_or(NovaScalar::from(0u64));
            let dm = delta_mul_m.get_value().unwrap_or(NovaScalar::from(0u64));
            let qq = q_mul_quot0.get_value().unwrap_or(NovaScalar::from(0u64));
            Ok(ct0_vals[l] - pu - e0_val - dm - qq)
        })?;

        cs.enforce(
            || format!("bfv_term0_c_{l}"),
            |lc| {
                lc + ct0_vars[l].get_variable()
                    - pk0_mul_u.get_variable()
                    - e0_var.get_variable()
                    - delta_mul_m.get_variable()
                    - q_mul_quot0.get_variable()
            },
            |lc| lc + CS::one(),
            |lc| lc + term.get_variable(),
        );

        let weighted = gamma_vars[l].mul(cs.namespace(|| format!("bfv_gamma0_w_{l}")), &term)?;
        acc0 = acc0.add(cs.namespace(|| format!("bfv_acc0_a_{l}")), &weighted)?;
    }

    cs.enforce(
        || "bfv_ct0_eq_zero",
        |lc| lc + CS::one(),
        |lc| lc + acc0.get_variable(),
        |lc| lc + zero_val.get_variable(),
    );

    // ct1 equation: Σ_l γ^l · (ct1[l] - pk1[l]·u - e1 - q[l]·quot1[l]) == 0
    let mut acc1 = AllocatedNum::alloc(cs.namespace(|| "bfv_acc1_init"), || {
        Ok(NovaScalar::from(0u64))
    })?;

    for l in 0..bfv_encryption_circuit::BFV_L {
        let pk1_mul_u = pk1_vars[l].mul(cs.namespace(|| format!("bfv_pk1u_{l}")), &u_var)?;
        let q_mul_quot1 =
            q_consts[l].mul(cs.namespace(|| format!("bfv_qquot1_{l}")), &quot1_vars[l])?;

        let term = AllocatedNum::alloc(cs.namespace(|| format!("bfv_term1_{l}")), || {
            let pu = pk1_mul_u.get_value().unwrap_or(NovaScalar::from(0u64));
            let qq = q_mul_quot1.get_value().unwrap_or(NovaScalar::from(0u64));
            Ok(ct1_vals[l] - pu - e1_val - qq)
        })?;

        cs.enforce(
            || format!("bfv_term1_c_{l}"),
            |lc| {
                lc + ct1_vars[l].get_variable()
                    - pk1_mul_u.get_variable()
                    - e1_var.get_variable()
                    - q_mul_quot1.get_variable()
            },
            |lc| lc + CS::one(),
            |lc| lc + term.get_variable(),
        );

        let weighted = gamma_vars[l].mul(cs.namespace(|| format!("bfv_gamma1_w_{l}")), &term)?;
        acc1 = acc1.add(cs.namespace(|| format!("bfv_acc1_a_{l}")), &weighted)?;
    }

    cs.enforce(
        || "bfv_ct1_eq_zero",
        |lc| lc + CS::one(),
        |lc| lc + acc1.get_variable(),
        |lc| lc + zero_val.get_variable(),
    );

    let bu = bfv_encryption_circuit::B_U;
    let be = bfv_encryption_circuit::B_E;
    let bm = bfv_encryption_circuit::B_M;

    norm_range_check_bp(
        cs,
        &u_var,
        extract_native_u64(&step_data[15]),
        bu,
        "bfv_u_norm",
    )?;
    norm_range_check_bp(
        cs,
        &e0_var,
        extract_native_u64(&step_data[16]),
        be,
        "bfv_e0_norm",
    )?;
    norm_range_check_bp(
        cs,
        &e1_var,
        extract_native_u64(&step_data[17]),
        be,
        "bfv_e1_norm",
    )?;
    norm_range_check_bp(
        cs,
        &m_var,
        extract_native_u64(&step_data[18]),
        bm,
        "bfv_m_norm",
    )?;

    AllocatedNum::alloc(cs.namespace(|| "bfv_ok"), || Ok(NovaScalar::from(1u64)))
}

fn extract_native_u64(fr: &ark_bn254::Fr) -> u64 {
    let bytes = fr.into_bigint().to_bytes_le();
    let mut buf = [0u8; 8];
    let len = bytes.len().min(8);
    buf[..len].copy_from_slice(&bytes[..len]);
    u64::from_le_bytes(buf)
}

fn norm_range_check_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    value: &AllocatedNum<NovaScalar>,
    native_value: u64,
    bound_u64: u64,
    tag: &str,
) -> Result<(), SynthesisError> {
    if native_value > bound_u64 {
        let one = AllocatedNum::alloc(cs.namespace(|| format!("{tag}_fail")), || {
            Ok(NovaScalar::from(1u64))
        })?;
        let zero = AllocatedNum::alloc(cs.namespace(|| format!("{tag}_fail_zero")), || {
            Ok(NovaScalar::from(0u64))
        })?;
        cs.enforce(
            || format!("{tag}_bound_fail"),
            |lc| lc + CS::one(),
            |lc| lc + one.get_variable(),
            |lc| lc + zero.get_variable(),
        );
        return Ok(());
    }

    let bits: Vec<AllocatedNum<NovaScalar>> = (0..31)
        .map(|idx| {
            let bit_val = NovaScalar::from((native_value >> idx) & 1);
            AllocatedNum::alloc(cs.namespace(|| format!("{tag}_bit_{idx}")), || Ok(bit_val))
        })
        .collect::<Result<_, _>>()?;

    for idx in 0..31 {
        let bit_val = NovaScalar::from((native_value >> idx) & 1);
        let bit_minus_one_val = bit_val - NovaScalar::from(1u64);

        let bit_minus_one =
            AllocatedNum::alloc(cs.namespace(|| format!("{tag}_bv_bmo_{idx}")), || {
                Ok(bit_minus_one_val)
            })?;

        cs.enforce(
            || format!("{tag}_bv_bmo_c_{idx}"),
            |lc| lc + CS::one(),
            |lc| lc + bit_minus_one.get_variable(),
            |lc| lc + bits[idx].get_variable() - CS::one(),
        );

        let prod = bits[idx].mul(
            cs.namespace(|| format!("{tag}_bv_prod_{idx}")),
            &bit_minus_one,
        )?;
        let zero_val = AllocatedNum::alloc(cs.namespace(|| format!("{tag}_bv_z_{idx}")), || {
            Ok(NovaScalar::from(0u64))
        })?;
        cs.enforce(
            || format!("{tag}_bit_check_{idx}"),
            |lc| lc + CS::one(),
            |lc| lc + prod.get_variable(),
            |lc| lc + zero_val.get_variable(),
        );
    }

    let mut acc = AllocatedNum::alloc(cs.namespace(|| format!("{tag}_rec_init")), || {
        Ok(NovaScalar::from(0u64))
    })?;
    let mut pow2 = NovaScalar::from(1u64);

    for idx in 0..31 {
        let pow2_const =
            AllocatedNum::alloc(cs.namespace(|| format!("{tag}_pow2_{idx}")), || Ok(pow2))?;
        let scaled = bits[idx].mul(cs.namespace(|| format!("{tag}_scale_{idx}")), &pow2_const)?;
        acc = acc.add(cs.namespace(|| format!("{tag}_acc_{idx}")), &scaled)?;
        pow2 = pow2.double();
    }

    cs.enforce(
        || format!("{tag}_reconstruct"),
        |lc| lc + CS::one(),
        |lc| lc + acc.get_variable(),
        |lc| lc + value.get_variable(),
    );

    Ok(())
}
