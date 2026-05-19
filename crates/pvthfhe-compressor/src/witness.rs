//! Witness generation pipeline for C7 decryption aggregation.
//!
//! Uses Poseidon sponge hashing for share coefficient commitments,
//! computes polynomial evaluations, and verifies commitments
//! off-circuit before Nova folding.

use ark_bn254::Fr;
use ark_ff::{Field, Zero};

use crate::poly_eval::eval_poly_bn254;
use crate::sonobe::poseidon_gadget::PoseidonParams;

// ── Native Poseidon permutation (duplicated from poseidon_gadget.rs) ────
// These match the private native helpers in poseidon_gadget.rs exactly.
// Duplicated here because P1.1 must not modify poseidon_gadget.rs.

fn native_ark(state: &mut [Fr], rk: &[Fr]) {
    for (s, k) in state.iter_mut().zip(rk.iter()) {
        *s += k;
    }
}

fn native_full_sbox(state: &mut [Fr]) {
    let alpha = [5u64];
    for s in state.iter_mut() {
        *s = s.pow(alpha);
    }
}

fn native_partial_sbox(state: &mut [Fr]) {
    state[0] = state[0].pow([5u64]);
}

fn native_mix(state: &mut [Fr], mds: &[Vec<Fr>]) {
    let t = state.len();
    let mut new_state = vec![Fr::zero(); t];
    for i in 0..t {
        for j in 0..t {
            new_state[i] += mds[i][j] * state[j];
        }
    }
    state.clone_from_slice(&new_state);
}

fn native_permute(state: &mut [Fr], params: &PoseidonParams<Fr>) {
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

// ── hash_all_coeffs / poseidon_sponge_hash_native ─────────────────────────

/// Compute a Poseidon sponge hash over an arbitrary slice of field elements.
///
/// This is the generic native Poseidon sponge, suitable for commitment
/// binding of arbitrary protocol fields. Absorbs all elements into the
/// sponge and squeezes one field element. Matches the in-circuit
/// `PoseidonSpongeVar` absorb-then-squeeze behaviour exactly.
///
/// Canonical BN254 Poseidon config: rate = 4, capacity = 1, t = 5.
pub fn poseidon_sponge_hash_native(fields: &[Fr]) -> Fr {
    hash_all_coeffs(fields)
}

/// Compute a Poseidon sponge hash of all share coefficients.
///
/// Absorbs every element in `coeffs` into a Poseidon sponge and squeezes
/// one field element.  This matches the in-circuit `PoseidonSpongeVar`
/// absorb-then-squeeze behaviour exactly: rate = 4, capacity = 1, t = 5
/// (canonical BN254 Poseidon config).
///
/// This is the native counterpart of the in-circuit commitment opening
/// (G2a) that will replace the current Merkle-tree commitment.
pub fn hash_all_coeffs(coeffs: &[Fr]) -> Fr {
    let params = PoseidonParams::<Fr>::canonical();
    let capacity = params.capacity;
    let rate = params.rate;
    let mut state = vec![Fr::zero(); params.t];

    let mut offset = 0;
    while offset < coeffs.len() {
        let remaining = coeffs.len() - offset;
        let space = rate;

        if remaining <= space {
            for (i, input) in coeffs[offset..].iter().enumerate() {
                state[capacity + i] += input;
            }
            offset = coeffs.len();
        } else {
            for i in 0..space {
                state[capacity + i] += coeffs[offset + i];
            }
            offset += space;
            native_permute(&mut state, &params);
        }
    }

    // Squeeze: permute then return first rate element (state[capacity])
    native_permute(&mut state, &params);
    state[capacity]
}

/// A single participant's C7 witness.
#[derive(Clone, Debug)]
pub struct C7Witness {
    /// Poseidon sponge hash of all 8192 share coefficients.
    pub coeff_commitment: Fr,
    /// Polynomial evaluation d_i(r) = Σ coeffs[j] * r^{N-1-j}.
    pub share_eval: Fr,
    /// Lagrange coefficient λ_i for this participant.
    pub lagrange_coeff: Fr,
    /// Share polynomial coefficients (N=8192 field elements).
    /// Used by the C7DecryptAggregationCircuit for in-circuit
    /// evaluation verification (G2).
    pub coeffs: Vec<Fr>,
}

/// A set of C7 witnesses for all participants in a decryption round.
#[derive(Clone, Debug)]
pub struct C7WitnessSet {
    /// Witness for each participant.
    pub participants: Vec<C7Witness>,
    /// Challenge point r used for polynomial evaluation.
    pub challenge_r: Fr,
    /// G.20: Prover randomness to prevent precomputation attacks.
    /// Included in native challenge derivation; in-circuit verification
    /// awaits ExternalInputs enlargement (deferred to G.12).
    pub prover_nonce: Fr,
}

impl C7WitnessSet {
    /// Construct a `C7WitnessSet` from share coefficients, Lagrange coefficients,
    /// and a challenge point.
    ///
    /// For each participant:
    /// 1. Commits to their share coefficients via Poseidon sponge hash.
    /// 2. Evaluates the share polynomial at `challenge_r`.
    ///
    /// # Arguments
    /// * `shares` - For each participant, a Vec of N=8192 share coefficients.
    /// * `lagrange_coeffs` - Lagrange coefficient λ_i for each participant.
    /// * `challenge_r` - Challenge point for polynomial evaluation.
    /// * `prover_nonce` - G.20: Prover randomness in challenge derivation.
    ///
    /// # Panics
    /// Panics if `shares.len() != lagrange_coeffs.len()`.
    pub fn new(
        shares: &[Vec<Fr>],
        lagrange_coeffs: &[Fr],
        challenge_r: Fr,
        prover_nonce: Fr,
    ) -> Self {
        assert_eq!(
            shares.len(),
            lagrange_coeffs.len(),
            "shares and lagrange_coeffs must have same length"
        );

        let mut participants = Vec::with_capacity(shares.len());

        for (i, coeffs) in shares.iter().enumerate() {
            let coeff_commitment = hash_all_coeffs(coeffs);
            let share_eval = eval_poly_bn254(coeffs, challenge_r);

            participants.push(C7Witness {
                coeff_commitment,
                share_eval,
                lagrange_coeff: lagrange_coeffs[i],
                coeffs: coeffs.clone(),
            });
        }

        Self {
            participants,
            challenge_r,
            prover_nonce,
        }
    }

    /// Verify all coefficient commitments in the witness set.
    ///
    /// Returns `true` if every participant's `coeff_commitment` matches
    /// the Poseidon sponge hash of their `coeffs`.
    /// Must be called before Nova folding to ensure input integrity.
    pub fn verify_commitments(&self) -> bool {
        for witness in &self.participants {
            if hash_all_coeffs(&witness.coeffs) != witness.coeff_commitment {
                return false;
            }
        }
        true
    }

    /// Verify that the Lagrange coefficients sum to 1 (off-circuit sanity check).
    ///
    /// The Nova circuit enforces this incrementally; this check catches
    /// input errors early.
    pub fn verify_lagrange_sum(&self) -> bool {
        let sum: Fr = self
            .participants
            .iter()
            .map(|w| w.lagrange_coeff)
            .fold(Fr::from(0u64), |a, b| a + b);
        sum == Fr::from(1u64)
    }
}

/// Witness data for one step of ShareVerificationStepCircuit.
#[derive(Clone, Debug)]
pub struct ShareVerificationWitness {
    /// Share coefficient values.
    pub coeffs: Vec<Fr>,
    /// Signature R-point x-coordinate as Fr.
    pub sig_r_x: Fr,
    /// Signature R-point y-coordinate as Fr.
    pub sig_r_y: Fr,
    /// Signature scalar s.
    pub sig_s: Fr,
    /// Signing public key x-coordinate as Fr.
    pub pk_x: Fr,
    /// Signing public key y-coordinate as Fr.
    pub pk_y: Fr,
}

/// Collection of share verification witnesses for all participants.
#[derive(Clone, Debug)]
pub struct ShareVerificationWitnessSet {
    pub witnesses: Vec<ShareVerificationWitness>,
}

impl ShareVerificationWitnessSet {
    pub fn verify_commitments(&self) -> bool {
        if self.witnesses.is_empty() {
            return false;
        }
        self.witnesses.iter().all(|w| !w.coeffs.is_empty())
    }
}

/// Witness data for one step of AjtaiCommitmentStepCircuit.
#[derive(Clone, Debug)]
pub struct AjtaiCommitmentWitness {
    /// Secret key share coefficients (256 × i64 coefficients in R_q).
    pub coeffs: Vec<Fr>,
    /// Expected commitment hash from the PVSS registry.
    pub expected_commitment_hash: Fr,
    /// Matrix derivation seed (session_id || party_index).
    pub matrix_seed: [u8; 32],
}

/// Collection of Ajtai commitment witnesses for all participants.
#[derive(Clone, Debug)]
pub struct AjtaiCommitmentWitnessSet {
    pub witnesses: Vec<AjtaiCommitmentWitness>,
}

impl AjtaiCommitmentWitnessSet {
    pub fn verify_commitments(&self) -> bool {
        if self.witnesses.is_empty() {
            return false;
        }
        self.witnesses.iter().all(|w| !w.coeffs.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sonobe::poseidon_gadget::PoseidonSpongeVar;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::GR1CSVar;
    use ark_relations::gr1cs::ConstraintSystem;

    /// Number of share polynomial coefficients (must match c7_circuit.rs:27).
    const N_COEFFS: usize = 8192;

    #[test]
    fn witness_set_empty_shares() {
        let set = C7WitnessSet::new(&[], &[], Fr::from(42u64), Fr::from(0u64));
        assert!(set.verify_commitments());
    }

    #[test]
    fn witness_set_single_share_trivial() {
        let coeffs: Vec<Fr> = (0..8).map(|i| Fr::from(i as u64)).collect();
        let set = C7WitnessSet::new(
            &[coeffs],
            &[Fr::from(1u64)],
            Fr::from(3u64),
            Fr::from(7u64),
        );
        assert!(set.verify_commitments());
        assert!(set.verify_lagrange_sum());
    }

    #[test]
    fn witness_set_bad_commitment_rejected() {
        let coeffs: Vec<Fr> = (0..8).map(|i| Fr::from(i as u64)).collect();
        let mut set = C7WitnessSet::new(
            &[coeffs],
            &[Fr::from(1u64)],
            Fr::from(3u64),
            Fr::from(7u64),
        );
        set.participants[0].coeff_commitment += Fr::from(1u64);
        assert!(!set.verify_commitments());
    }

    #[test]
    fn test_hash_all_coeffs_deterministic() {
        let coeffs: Vec<Fr> = (0..N_COEFFS).map(|i| Fr::from(i as u64)).collect();
        let h1 = hash_all_coeffs(&coeffs);
        let h2 = hash_all_coeffs(&coeffs);
        assert_eq!(h1, h2, "hash_all_coeffs must be deterministic");

        let coeffs2: Vec<Fr> = (1..=N_COEFFS).map(|i| Fr::from(i as u64)).collect();
        let h3 = hash_all_coeffs(&coeffs2);
        assert_ne!(h1, h3, "different inputs must produce different hashes");
    }

    #[test]
    fn test_hash_all_coeffs_matches_circuit() {
        // Use a modest size — sponge absorb/squeeze logic is identical at any size.
        let n = 16;
        let coeffs: Vec<Fr> = (0..n).map(|i| Fr::from(i as u64)).collect();

        let native_result = hash_all_coeffs(&coeffs);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut sponge = PoseidonSpongeVar::new();
        let input_vars: Vec<FpVar<Fr>> = coeffs
            .iter()
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(*v)).unwrap())
            .collect();

        sponge.absorb(&input_vars).unwrap();
        let circuit_result = sponge.squeeze_one().unwrap();

        assert_eq!(
            circuit_result.value().unwrap(),
            native_result,
            "circuit PoseidonSpongeVar result must match native hash_all_coeffs"
        );
        assert!(
            cs.is_satisfied().unwrap(),
            "constraint system must be satisfied"
        );
    }
}
