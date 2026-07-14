use crate::{
    ajtai::{AjtaiCommitment, AjtaiParams},
    ring::{ring_add_poly, scalar_mul, RqPoly, Q_COMMIT},
    CycloError,
};

pub struct FoldedAccumulator {
    pub commitment: AjtaiCommitment,
    pub folded_witness: Vec<RqPoly>,
    pub norm_bound: u64,
    pub fold_depth: u32,
    pub ajtai_params: AjtaiParams,
}

pub fn fold_instances(
    acc: &FoldedAccumulator,
    instances: &[AjtaiCommitment],
    witnesses: &[Vec<RqPoly>],
    r: u64,
) -> Result<FoldedAccumulator, CycloError> {
    if instances.len() != witnesses.len() {
        return Err(CycloError::InvalidInstance(
            "instances and witnesses length mismatch",
        ));
    }

    let m = acc.commitment.commitment.len();

    if instances.is_empty() {
        return Ok(FoldedAccumulator {
            commitment: acc.commitment.clone(),
            folded_witness: acc.folded_witness.clone(),
            norm_bound: acc.norm_bound,
            fold_depth: acc.fold_depth,
            ajtai_params: acc.ajtai_params.clone(),
        });
    }

    let mut combined_polys: Vec<RqPoly> = acc.commitment.commitment.clone();
    let mut combined_witness: Vec<RqPoly> = acc.folded_witness.clone();

    let n = acc.folded_witness.len();

    for ((inst, wit), power) in instances
        .iter()
        .zip(witnesses.iter())
        .zip(1u32..)
    {
        if inst.commitment.len() != m {
            return Err(CycloError::InvalidInstance(
                "instance commitment length must match accumulator",
            ));
        }
        if wit.len() != n {
            return Err(CycloError::InvalidInstance(
                "witness length must match accumulator witness",
            ));
        }

        let coeff = pow_mod(r as u128, power, Q_COMMIT as u128) as u64;

        for poly_idx in 0..m {
            combined_polys[poly_idx] = ring_add_poly(
                &combined_polys[poly_idx],
                &scalar_mul(&inst.commitment[poly_idx], coeff as u128),
            );
        }

        for wit_idx in 0..n {
            combined_witness[wit_idx] = ring_add_poly(
                &combined_witness[wit_idx],
                &scalar_mul(&wit[wit_idx], coeff as u128),
            );
        }
    }

    let new_depth = acc.fold_depth + instances.len() as u32;

    Ok(FoldedAccumulator {
        commitment: AjtaiCommitment {
            commitment: combined_polys,
        },
        folded_witness: combined_witness,
        norm_bound: acc.norm_bound,
        fold_depth: new_depth,
        ajtai_params: acc.ajtai_params.clone(),
    })
}

pub fn fold_commitments(acc: &AjtaiCommitment, instances: &[AjtaiCommitment], r: u64) -> AjtaiCommitment {
    let m = acc.commitment.len();
    if instances.is_empty() {
        return acc.clone();
    }
    let mut combined: Vec<RqPoly> = acc.commitment.clone();
    for (inst, power) in instances.iter().zip(1u32..) {
        let coeff = pow_mod(r as u128, power, Q_COMMIT as u128) as u64;
        for poly_idx in 0..m {
            combined[poly_idx] = ring_add_poly(
                &combined[poly_idx],
                &scalar_mul(&inst.commitment[poly_idx], coeff as u128),
            );
        }
    }
    AjtaiCommitment { commitment: combined }
}

pub fn verify_fold(acc: &FoldedAccumulator, _instances: &[AjtaiCommitment], _r: u64) -> bool {
    let params = &acc.ajtai_params;

    match crate::ajtai::commit(params, &acc.folded_witness, &mut rand_core::OsRng) {
        Ok(computed_commitment) => {
            computed_commitment.commitment == acc.commitment.commitment
        }
        Err(_) => false,
    }
}

fn pow_mod(base: u128, exp: u32, modulus: u128) -> u128 {
    if exp == 0 {
        return 1u128 % modulus;
    }
    let mut result = 1u128;
    let mut b = base % modulus;
    let mut e = exp;
    loop {
        if e & 1 == 1 {
            result = (result * b) % modulus;
        }
        e >>= 1;
        if e == 0 {
            break;
        }
        b = (b * b) % modulus;
    }
    result
}
