use std::time::Instant;

const MODULUS: u64 = 4_294_967_291;
const FOLD_WORK_ROUNDS: usize = 512;

#[derive(Debug, Clone)]
pub struct R1csInstance {
    pub witness: Vec<u64>,
    pub a_evals: Vec<u64>,
    pub b_evals: Vec<u64>,
    pub c_evals: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct FoldAccumulator {
    pub fold_count: usize,
    pub weight_sum: u64,
    pub witness_sum: Vec<u64>,
    pub a_sum: Vec<u64>,
    pub b_sum: Vec<u64>,
    pub c_sum: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct FinalSnarkProof {
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct FoldRunSummary {
    pub accumulator: FoldAccumulator,
    pub total_fold_ms: f64,
}

pub fn sample_r1cs_instance() -> R1csInstance {
    let witness = vec![1, 3, 5, 7, 11, 13, 17, 19];
    let a_evals = witness.clone();
    let b_evals: Vec<u64> = witness.iter().copied().cycle().skip(1).take(witness.len()).collect();
    let c_evals = a_evals
        .iter()
        .zip(b_evals.iter())
        .map(|(left, right)| ((*left as u128 * *right as u128) % MODULUS as u128) as u64)
        .collect();

    R1csInstance {
        witness,
        a_evals,
        b_evals,
        c_evals,
    }
}

pub fn fold_instances(instance: &R1csInstance, copies: usize) -> FoldAccumulator {
    run_folding_loop(instance, copies).accumulator
}

pub fn run_folding_loop(instance: &R1csInstance, copies: usize) -> FoldRunSummary {
    assert!(copies > 0, "copies must be positive");
    let mut accumulator = FoldAccumulator {
        fold_count: 0,
        weight_sum: 0,
        witness_sum: vec![0; instance.witness.len()],
        a_sum: vec![0; instance.a_evals.len()],
        b_sum: vec![0; instance.b_evals.len()],
        c_sum: vec![0; instance.c_evals.len()],
    };

    let start = Instant::now();
    for index in 0..copies {
        fold_into(&mut accumulator, instance, challenge_for(index));
    }

    FoldRunSummary {
        accumulator,
        total_fold_ms: start.elapsed().as_secs_f64() * 1_000.0,
    }
}

pub fn accumulator_size_bytes(accumulator: &FoldAccumulator) -> usize {
    std::mem::size_of::<usize>() * 2
        + std::mem::size_of::<u64>()
        + (accumulator.witness_sum.len()
            + accumulator.a_sum.len()
            + accumulator.b_sum.len()
            + accumulator.c_sum.len())
            * std::mem::size_of::<u64>()
}

pub fn prove_final_snark(accumulator: &FoldAccumulator, instance: &R1csInstance) -> FinalSnarkProof {
    assert!(verify_folded_instance(accumulator, instance), "accumulator must verify before final proof");
    let byte_len = expected_final_snark_bytes(accumulator.fold_count);
    let mut state = [0x243f_6a88_u64, 0x85a3_08d3_u64, 0x1319_8a2e_u64, 0x0370_7344_u64];
    absorb_into_state(&mut state, accumulator.weight_sum);
    absorb_slice(&mut state, &accumulator.witness_sum);
    absorb_slice(&mut state, &accumulator.a_sum);
    absorb_slice(&mut state, &accumulator.b_sum);
    absorb_slice(&mut state, &accumulator.c_sum);

    let mut bytes = vec![0_u8; byte_len];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let lane = index % state.len();
        state[lane] = mix_word(state[lane], (index as u64) + accumulator.fold_count as u64 + 1);
        *byte = (state[lane] & 0xff) as u8;
    }

    FinalSnarkProof { bytes }
}

pub fn verify_final_snark(proof: &FinalSnarkProof, accumulator: &FoldAccumulator, instance: &R1csInstance) -> bool {
    if !verify_folded_instance(accumulator, instance) {
        return false;
    }

    if proof.bytes.len() != expected_final_snark_bytes(accumulator.fold_count) {
        return false;
    }

    proof.bytes == prove_final_snark(accumulator, instance).bytes
}

pub fn expected_final_snark_bytes(fold_count: usize) -> usize {
    let log_rounds = if fold_count <= 1 {
        0
    } else {
        (usize::BITS - (fold_count - 1).leading_zeros()) as usize
    };
    192 + 32 * log_rounds
}

pub fn verify_folded_instance(accumulator: &FoldAccumulator, instance: &R1csInstance) -> bool {
    if accumulator.fold_count == 0 {
        return false;
    }

    let expected_witness = scale_vector(&instance.witness, accumulator.weight_sum);
    let expected_a = scale_vector(&instance.a_evals, accumulator.weight_sum);
    let expected_b = scale_vector(&instance.b_evals, accumulator.weight_sum);
    let expected_c = scale_vector(&instance.c_evals, accumulator.weight_sum);

    accumulator.witness_sum == expected_witness
        && accumulator.a_sum == expected_a
        && accumulator.b_sum == expected_b
        && accumulator.c_sum == expected_c
        && accumulator
            .a_sum
            .iter()
            .zip(accumulator.b_sum.iter())
            .zip(accumulator.c_sum.iter())
            .all(|((left, right), output)| mod_mul(*left, *right) == mod_mul(accumulator.weight_sum, *output))
}

fn challenge_for(index: usize) -> u64 {
    let mut x = (index as u64).wrapping_add(1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    (x % (MODULUS - 1)).saturating_add(1)
}

fn fold_into(accumulator: &mut FoldAccumulator, instance: &R1csInstance, challenge: u64) {
    accumulator.fold_count += 1;
    accumulator.weight_sum = mod_add(accumulator.weight_sum, challenge);
    mix_scaled_vector(&mut accumulator.witness_sum, &instance.witness, challenge);
    mix_scaled_vector(&mut accumulator.a_sum, &instance.a_evals, challenge);
    mix_scaled_vector(&mut accumulator.b_sum, &instance.b_evals, challenge);
    mix_scaled_vector(&mut accumulator.c_sum, &instance.c_evals, challenge);

    let mut sponge = challenge;
    for _ in 0..FOLD_WORK_ROUNDS {
        sponge = mix_word(sponge, accumulator.weight_sum);
        for lane in [&mut accumulator.a_sum, &mut accumulator.b_sum, &mut accumulator.c_sum] {
            for value in lane.iter_mut() {
                let sponge_mod = sponge % MODULUS;
                *value = mod_add(*value, sponge_mod);
                *value = mod_add(*value, MODULUS - sponge_mod);
                sponge = mix_word(sponge, *value);
            }
        }
    }
}

fn mix_scaled_vector(target: &mut [u64], source: &[u64], scale: u64) {
    for (target_value, source_value) in target.iter_mut().zip(source.iter()) {
        *target_value = mod_add(*target_value, mod_mul(scale, *source_value));
    }
}

fn scale_vector(source: &[u64], scale: u64) -> Vec<u64> {
    source.iter().map(|value| mod_mul(*value, scale)).collect()
}

fn absorb_slice(state: &mut [u64; 4], values: &[u64]) {
    for value in values {
        absorb_into_state(state, *value);
    }
}

fn absorb_into_state(state: &mut [u64; 4], value: u64) {
    for (offset, lane) in state.iter_mut().enumerate() {
        *lane = mix_word(*lane, value.wrapping_add(offset as u64));
    }
}

fn mix_word(lhs: u64, rhs: u64) -> u64 {
    lhs.rotate_left(13) ^ rhs.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

fn mod_add(lhs: u64, rhs: u64) -> u64 {
    ((lhs as u128 + rhs as u128) % MODULUS as u128) as u64
}

fn mod_mul(lhs: u64, rhs: u64) -> u64 {
    ((lhs as u128 * rhs as u128) % MODULUS as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::{fold_instances, sample_r1cs_instance, verify_folded_instance};

    #[test]
    fn folded_instance_verifier_accepts_valid_accumulator() {
        let instance = sample_r1cs_instance();
        let accumulator = fold_instances(&instance, 16);

        assert!(verify_folded_instance(&accumulator, &instance));
    }
}
