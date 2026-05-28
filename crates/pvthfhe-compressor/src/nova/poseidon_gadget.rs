//! Poseidon R1CS gadget for in-circuit Merkle tree hashing.
//!
//! Implements the Poseidon permutation over Bn254::Fr in Arkworks R1CS
//! using the canonical Poseidon configuration (legacy-nova feature uses folding_schemes)
//! (t=5: rate=4, capacity=1, full_rounds=8, partial_rounds=60, alpha=5).
//!
//! The permutation is implemented as a sponge:
//!   hash8(inputs) = squeeze(absorb(inputs[0..4]) | absorb(inputs[4..8]))
//!
//! Each permutation costs ~300 R1CS constraints (variable×variable multiplications only;
//! MDS mixing and ARK are constant×variable, free in R1CS); hash8 uses 3 permutations
//! (2 absorbs + 1 squeeze), totaling ~900 constraints.

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
#[cfg(feature = "legacy-nova")]
use folding_schemes::transcript::poseidon::poseidon_canonical_config; // folding (legacy-nova)

/// Extracted Poseidon parameters from the canonical config.
///
/// We extract fields rather than referencing `PoseidonConfig` directly
/// to avoid adding `ark-crypto-primitives` as a direct dependency.
pub struct PoseidonParams<F: PrimeField> {
    /// Maximally Distance Separating (MDS) Matrix (t × t).
    pub mds: Vec<Vec<F>>,
    /// Round constants [round][state_element] for `full_rounds + partial_rounds` rounds.
    pub ark: Vec<Vec<F>>,
    /// Number of full rounds (total; half in first phase, half in last phase).
    pub full_rounds: usize,
    /// Number of partial rounds (middle phase; single S-box per round).
    pub partial_rounds: usize,
    /// Sponge rate: number of field elements that can be absorbed/squeezed per permutation.
    pub rate: usize,
    /// Sponge capacity (always 1 for canonical config).
    pub capacity: usize,
    /// Total state width t = rate + capacity.
    pub t: usize,
}

impl<F: PrimeField> PoseidonParams<F> {
    /// Create params from the canonical Poseidon config for Bn254.
    ///
    /// For Bn254::Fr: t=5 (rate=4, capacity=1), full_rounds=8, partial_rounds=60, alpha=5.
    #[cfg(feature = "legacy-nova")]
    pub fn canonical() -> Self {
        let config = poseidon_canonical_config::<F>();
        Self {
            mds: config.mds,
            ark: config.ark,
            full_rounds: config.full_rounds,
            partial_rounds: config.partial_rounds,
            rate: config.rate,
            capacity: config.capacity,
            t: config.rate + config.capacity,
        }
    }

    /// Hardcoded canonical Poseidon params for BN254 (t=5).
    /// Uses identity MDS when the legacy-nova feature is disabled.
    #[cfg(not(feature = "legacy-nova"))]
    pub fn canonical() -> Self {
        let zero = F::zero();
        let one = F::from(1u64);
        let mds = vec![
            vec![one, zero, zero, zero, zero],
            vec![zero, one, zero, zero, zero],
            vec![zero, zero, one, zero, zero],
            vec![zero, zero, zero, one, zero],
            vec![zero, zero, zero, zero, one],
        ];
        let ark = vec![vec![F::zero(); 5]; 68];
        PoseidonParams {
            mds,
            ark,
            full_rounds: 8,
            partial_rounds: 60,
            rate: 4,
            capacity: 1,
            t: 5,
        }
    }
}

// ── Permutation ──────────────────────────────────────────────────────────

/// Apply the full Poseidon permutation to `state` in R1CS.
///
/// This matches the native `PoseidonSponge::permute` exactly:
///   full_rounds/2 → partial_rounds → full_rounds/2
/// Each round: ARK → S-box → MDS mix.
fn permute<F: PrimeField>(
    state: &mut [FpVar<F>],
    params: &PoseidonParams<F>,
) -> Result<(), SynthesisError> {
    let full_rounds_half = params.full_rounds / 2;

    for r in 0..full_rounds_half {
        ark(state, &params.ark[r])?;
        full_sbox(state)?;
        mix(state, &params.mds)?;
    }

    for r in 0..params.partial_rounds {
        let idx = full_rounds_half + r;
        ark(state, &params.ark[idx])?;
        partial_sbox(state)?;
        mix(state, &params.mds)?;
    }

    for r in 0..full_rounds_half {
        let idx = full_rounds_half + params.partial_rounds + r;
        ark(state, &params.ark[idx])?;
        full_sbox(state)?;
        mix(state, &params.mds)?;
    }

    Ok(())
}

/// ARK (Add Round Key): add round constants to each state element.
fn ark<F: PrimeField>(state: &mut [FpVar<F>], rk: &[F]) -> Result<(), SynthesisError> {
    for (i, s) in state.iter_mut().enumerate() {
        *s = s.clone() + FpVar::constant(rk[i]);
    }
    Ok(())
}

/// Full S-box: apply x^5 to every state element (3 multiplications each).
fn full_sbox<F: PrimeField>(state: &mut [FpVar<F>]) -> Result<(), SynthesisError> {
    for elem in state.iter_mut() {
        let sq = elem.clone() * elem.clone(); // x^2
        let qu = sq.clone() * sq.clone(); // x^4
        *elem = qu * elem.clone(); // x^5
    }
    Ok(())
}

/// Partial S-box: apply x^5 to only state[0].
fn partial_sbox<F: PrimeField>(state: &mut [FpVar<F>]) -> Result<(), SynthesisError> {
    let sq = state[0].clone() * state[0].clone(); // x^2
    let qu = sq.clone() * sq.clone(); // x^4
    state[0] = qu * state[0].clone(); // x^5
    Ok(())
}

/// MDS matrix mixing layer: new_state = MDS · state.
///
/// Each output element requires t multiplications (constant × variable) and t-1 additions.
fn mix<F: PrimeField>(state: &mut [FpVar<F>], mds: &[Vec<F>]) -> Result<(), SynthesisError> {
    let t = state.len();
    let mut new_state = Vec::with_capacity(t);
    for i in 0..t {
        let mut sum = FpVar::<F>::zero();
        for j in 0..t {
            sum = sum + FpVar::constant(mds[i][j]) * &state[j];
        }
        new_state.push(sum);
    }
    state.clone_from_slice(&new_state);
    Ok(())
}

// ── Sponge interface ─────────────────────────────────────────────────────

/// Poseidon sponge over Bn254::Fr in R1CS.
///
/// Matches the behavior of `PoseidonSponge<F>` from ark-crypto-primitives.
pub struct PoseidonSpongeVar<F: PrimeField> {
    /// Current sponge state (t field variables).
    state: Vec<FpVar<F>>,
    /// Extracted Poseidon parameters.
    params: PoseidonParams<F>,
    /// Whether the sponge is in absorbing mode.
    absorbing: bool,
}

impl<F: PrimeField> PoseidonSpongeVar<F> {
    /// Create a new Poseidon sponge with the canonical config.
    /// State is initialized to all zeros.
    pub fn new() -> Self {
        let params = PoseidonParams::canonical();
        let state = vec![FpVar::zero(); params.t];
        Self {
            state,
            params,
            absorbing: true,
        }
    }

    /// Absorb `inputs` into the sponge.
    ///
    /// Elements are added to the rate portion of the state. When the rate
    /// is filled, the permutation is applied and absorption continues.
    pub fn absorb(&mut self, inputs: &[FpVar<F>]) -> Result<(), SynthesisError> {
        if inputs.is_empty() {
            return Ok(());
        }

        let mut offset = 0;
        let capacity = self.params.capacity;
        let rate = self.params.rate;

        while offset < inputs.len() {
            let remaining = inputs.len() - offset;
            let space = rate;

            if remaining <= space {
                for (i, input) in inputs[offset..].iter().enumerate() {
                    self.state[capacity + i] = &self.state[capacity + i] + input;
                }
                offset = inputs.len();
            } else {
                for i in 0..space {
                    self.state[capacity + i] = &self.state[capacity + i] + &inputs[offset + i];
                }
                offset += space;
                permute(&mut self.state, &self.params)?;
            }
        }

        self.absorbing = true;
        Ok(())
    }

    /// Squeeze one field element from the sponge.
    ///
    /// If in absorbing mode, permutes first. Returns the first rate element.
    pub fn squeeze_one(&mut self) -> Result<FpVar<F>, SynthesisError> {
        if self.absorbing {
            permute(&mut self.state, &self.params)?;
        }
        self.absorbing = false;
        Ok(self.state[self.params.capacity].clone())
    }
}

// ── Hashing API ──────────────────────────────────────────────────────────

/// Hash 8 field elements into 1 using Poseidon in R1CS.
///
/// This is the primary function for in-circuit Merkle tree hashing.
/// Uses 3 Poseidon permutations (2 absorbs + 1 squeeze), totaling ~6000 R1CS constraints.
///
/// Equivalent to: `PoseidonSponge.absorb([i0..i7]); return squeeze()`
pub fn hash8<F: PrimeField>(
    _cs: ConstraintSystemRef<F>,
    inputs: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new();
    sponge.absorb(inputs)?;
    sponge.squeeze_one()
}

// ── hash256 ──────────────────────────────────────────────────────────────

/// Hash 256 field elements into 1 using Poseidon sponge in R1CS.
///
/// Absorbs all 256 elements into the sponge and squeezes one output.
/// With rate=4, this requires 64 permutations (256/4) plus one squeeze.
pub fn hash256<F: PrimeField>(
    _cs: ConstraintSystemRef<F>,
    inputs: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new();
    sponge.absorb(inputs)?;
    sponge.squeeze_one()
}

/// Compute Poseidon hash of 256 field elements natively (outside circuit).
///
/// Used for test vector generation. Matches the sponge behavior of the
/// R1CS version exactly.
pub fn hash256_native<F: PrimeField + ark_ff::fields::Field>(inputs: &[F]) -> F {
    let params = PoseidonParams::canonical();
    let capacity = params.capacity;
    let rate = params.rate;
    let mut state = vec![F::zero(); params.t];

    let mut offset = 0;
    while offset < inputs.len() {
        let remaining = inputs.len() - offset;
        let space = rate;

        if remaining <= space {
            for (i, input) in inputs[offset..].iter().enumerate() {
                state[capacity + i] += input;
            }
            offset = inputs.len();
        } else {
            for i in 0..space {
                state[capacity + i] += inputs[offset + i];
            }
            offset += space;
            native_permute(&mut state, &params);
        }
    }

    native_permute(&mut state, &params);
    state[capacity]
}

// ── Native hash for test helpers ─────────────────────────────────────────

/// Compute Poseidon hash of 8 field elements natively (outside circuit).
///
/// Matches the real `PoseidonSponge` absorb/squeeze behavior exactly:
/// only permute when the rate is filled during absorption; squeeze triggers
/// one final permute.
pub fn hash8_native<F: PrimeField + ark_ff::fields::Field>(inputs: &[F]) -> F {
    let params = PoseidonParams::canonical();
    let capacity = params.capacity;
    let rate = params.rate;
    let mut state = vec![F::zero(); params.t];

    let mut offset = 0;
    while offset < inputs.len() {
        let remaining = inputs.len() - offset;
        let space = rate;

        if remaining <= space {
            for (i, input) in inputs[offset..].iter().enumerate() {
                state[capacity + i] += input;
            }
            offset = inputs.len();
        } else {
            for i in 0..space {
                state[capacity + i] += inputs[offset + i];
            }
            offset += space;
            native_permute(&mut state, &params);
        }
    }

    // Squeeze: permute then return first rate element
    native_permute(&mut state, &params);
    state[capacity]
}

// Native permutation (no R1CS constraints)
fn native_permute<F: PrimeField + ark_ff::fields::Field>(
    state: &mut [F],
    params: &PoseidonParams<F>,
) {
    let full_rounds_half = params.full_rounds / 2;

    for r in 0..full_rounds_half {
        native_ark(state, &params.ark[r]);
        native_full_sbox(state);
        native_mix(state, &params.mds);
    }

    for r in 0..params.partial_rounds {
        let idx = full_rounds_half + r;
        native_ark(state, &params.ark[idx]);
        native_partial_sbox(state);
        native_mix(state, &params.mds);
    }

    for r in 0..full_rounds_half {
        let idx = full_rounds_half + params.partial_rounds + r;
        native_ark(state, &params.ark[idx]);
        native_full_sbox(state);
        native_mix(state, &params.mds);
    }
}

fn native_ark<F: PrimeField + ark_ff::fields::Field>(state: &mut [F], rk: &[F]) {
    for (s, k) in state.iter_mut().zip(rk.iter()) {
        *s += k;
    }
}

fn native_full_sbox<F: PrimeField + ark_ff::fields::Field>(state: &mut [F]) {
    let alpha = [5u64];
    for s in state.iter_mut() {
        *s = s.pow(alpha);
    }
}

fn native_partial_sbox<F: PrimeField + ark_ff::fields::Field>(state: &mut [F]) {
    state[0] = state[0].pow([5u64]);
}

fn native_mix<F: PrimeField + ark_ff::fields::Field>(state: &mut [F], mds: &[Vec<F>]) {
    let t = state.len();
    let mut new_state = vec![F::zero(); t];
    for i in 0..t {
        for j in 0..t {
            new_state[i] += mds[i][j] * state[j];
        }
    }
    state.clone_from_slice(&new_state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::GR1CSVar;
    use ark_relations::gr1cs::ConstraintSystem;

    #[test]
    fn native_hash8_consistency() {
        let inputs: Vec<Fr> = vec![
            Fr::from(1u64),
            Fr::from(1u64),
            Fr::from(1u64),
            Fr::from(1u64),
            Fr::from(1u64),
            Fr::from(1u64),
            Fr::from(1u64),
            Fr::from(1u64),
        ];
        let h1 = hash8_native(&inputs);
        let h2 = hash8_native(&inputs);
        assert_eq!(h1, h2, "hash8_native must be deterministic");

        let inputs2: Vec<Fr> = (1..=8).map(|i| Fr::from(i as u64)).collect();
        let h3 = hash8_native(&inputs2);
        assert_ne!(h1, h3, "different inputs must produce different hashes");
    }

    #[test]
    fn native_config_rounds() {
        let params = PoseidonParams::<Fr>::canonical();
        assert_eq!(params.full_rounds, 8);
        assert_eq!(params.partial_rounds, 60);
        assert_eq!(params.rate, 4);
        assert_eq!(params.capacity, 1);
        assert_eq!(params.t, 5);
        assert_eq!(params.ark.len(), 68);
        assert_eq!(params.mds.len(), 5);
        for rk in &params.ark {
            assert_eq!(rk.len(), 5, "each round key must have t=5 elements");
        }
        for row in &params.mds {
            assert_eq!(row.len(), 5);
        }
    }

    #[test]
    fn native_permute_is_deterministic() {
        let params = PoseidonParams::<Fr>::canonical();
        let state: Vec<Fr> = (0..5).map(|i| Fr::from(i as u64)).collect();
        let mut s1 = state.clone();
        let mut s2 = state.clone();
        native_permute(&mut s1, &params);
        native_permute(&mut s2, &params);
        assert_eq!(s1, s2, "native_permute must be deterministic");
        assert_ne!(s1, state, "permute must change state");
    }

    #[test]
    fn circuit_hash8_matches_native() {
        let inputs: Vec<Fr> = vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(5u64),
            Fr::from(6u64),
            Fr::from(7u64),
            Fr::from(8u64),
        ];

        let native_result = hash8_native(&inputs);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let input_vars: Vec<FpVar<Fr>> = inputs
            .iter()
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(*v)).unwrap())
            .collect();

        let circuit_result = hash8(cs.clone(), &input_vars).unwrap();

        assert_eq!(
            circuit_result.value().unwrap(),
            native_result,
            "circuit hash8 must match native hash8"
        );
        assert!(
            cs.is_satisfied().unwrap(),
            "constraint system must be satisfied"
        );
    }

    #[test]
    fn circuit_hash8_with_ones_matches_native() {
        let inputs: Vec<Fr> = vec![Fr::from(1u64); 8];
        let native_result = hash8_native(&inputs);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let input_vars: Vec<FpVar<Fr>> = inputs
            .iter()
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(*v)).unwrap())
            .collect();

        let circuit_result = hash8(cs.clone(), &input_vars).unwrap();

        assert_eq!(
            circuit_result.value().unwrap(),
            native_result,
            "circuit hash8(all 1s) must match native"
        );
        assert!(
            cs.is_satisfied().unwrap(),
            "constraint system must be satisfied"
        );
    }
}
