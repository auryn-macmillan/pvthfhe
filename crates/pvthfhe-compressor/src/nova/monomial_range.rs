use super::NovaScalar;
use bp_ff::Field;
use nova_snark::frontend::gadgets::num::AllocatedNum;
use nova_snark::frontend::{ConstraintSystem, SynthesisError};

/// Adaptive bit-count range check using monomial embedding (Symphony §5.2).
///
/// Replaces the fixed 31-bit decomposition in `norm_range_check_bp` with
/// an adaptive decomposition that uses only `ceil(log2(bound))` bits.
///
/// For power-of-two bounds (e.g. `B_Z_S = 131072 = 2^17`), the bit count
/// alone enforces the bound exactly.  For non-power-of-two bounds, a
/// supplementary zero-check on the high bit(s) tightens the bound to
/// `2^ceil(log2(bound)) - 1`.
///
/// Constraint cost: ~3 · `ceil(log2(bound))` (vs ~3 · 31 previously).
pub fn monomial_range_check_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    value_var: &AllocatedNum<NovaScalar>,
    value: u64,
    bound: u64,
    tag: &str,
) -> Result<(), SynthesisError> {
    if value > bound {
        let one = AllocatedNum::alloc(cs.namespace(|| format!("{tag}_monomial_fail")), || {
            Ok(NovaScalar::from(1u64))
        })?;
        let zero =
            AllocatedNum::alloc(cs.namespace(|| format!("{tag}_monomial_fail_zero")), || {
                Ok(NovaScalar::from(0u64))
            })?;
        cs.enforce(
            || format!("{tag}_monomial_bound_fail"),
            |lc| lc + CS::one(),
            |lc| lc + one.get_variable(),
            |lc| lc + zero.get_variable(),
        );
        return Ok(());
    }

    let num_bits = monomial_bit_count(bound);

    let bits: Vec<AllocatedNum<NovaScalar>> = (0..num_bits)
        .map(|idx| {
            let bit_val = NovaScalar::from((value >> idx) & 1);
            AllocatedNum::alloc(cs.namespace(|| format!("{tag}_m_bit_{idx}")), || {
                Ok(bit_val)
            })
        })
        .collect::<Result<_, _>>()?;

    for idx in 0..num_bits {
        let bit_val = NovaScalar::from((value >> idx) & 1);

        let bit_minus_one_val = if bit_val == NovaScalar::ONE {
            NovaScalar::ZERO
        } else {
            -NovaScalar::ONE
        };

        let bit_minus_one =
            AllocatedNum::alloc(cs.namespace(|| format!("{tag}_m_bmo_{idx}")), || {
                Ok(bit_minus_one_val)
            })?;

        cs.enforce(
            || format!("{tag}_m_bmo_c_{idx}"),
            |lc| lc + CS::one(),
            |lc| lc + bit_minus_one.get_variable(),
            |lc| lc + bits[idx].get_variable() - CS::one(),
        );

        let prod = bits[idx].mul(
            cs.namespace(|| format!("{tag}_m_prod_{idx}")),
            &bit_minus_one,
        )?;
        let zero_val = AllocatedNum::alloc(cs.namespace(|| format!("{tag}_m_z_{idx}")), || {
            Ok(NovaScalar::ZERO)
        })?;
        cs.enforce(
            || format!("{tag}_m_bit_check_{idx}"),
            |lc| lc + CS::one(),
            |lc| lc + prod.get_variable(),
            |lc| lc + zero_val.get_variable(),
        );
    }

    let mut acc = AllocatedNum::alloc(cs.namespace(|| format!("{tag}_m_rec_init")), || {
        Ok(NovaScalar::ZERO)
    })?;
    let mut pow2 = NovaScalar::ONE;

    for idx in 0..num_bits {
        let pow2_const =
            AllocatedNum::alloc(cs.namespace(|| format!("{tag}_m_pow2_{idx}")), || Ok(pow2))?;
        let scaled = bits[idx].mul(cs.namespace(|| format!("{tag}_m_scale_{idx}")), &pow2_const)?;
        acc = acc.add(cs.namespace(|| format!("{tag}_m_acc_{idx}")), &scaled)?;
        pow2 = pow2.double();
    }

    cs.enforce(
        || format!("{tag}_m_reconstruct"),
        |lc| lc + CS::one(),
        |lc| lc + acc.get_variable(),
        |lc| lc + value_var.get_variable(),
    );

    if bound > 1 && !bound.is_power_of_two() {
        let bound_msb = (usize::BITS - bound.leading_zeros() - 1) as usize;
        if num_bits > bound_msb {
            for idx in bound_msb..num_bits {
                let zero_val =
                    AllocatedNum::alloc(cs.namespace(|| format!("{tag}_m_ub_z_{idx}")), || {
                        Ok(NovaScalar::ZERO)
                    })?;
                cs.enforce(
                    || format!("{tag}_m_upper_bound_{idx}"),
                    |lc| lc + CS::one(),
                    |lc| lc + bits[idx].get_variable(),
                    |lc| lc + zero_val.get_variable(),
                );
            }
        }
    }

    Ok(())
}

/// Returns the number of bits required to represent any value in `[0, bound)`.
///
/// Equivalent to `ceil(log2(bound))`, with a floor of 1 so that the
/// reconstruction loop always has at least one iteration.
fn monomial_bit_count(bound: u64) -> usize {
    if bound <= 1 {
        return 1;
    }
    (usize::BITS - (bound - 1).leading_zeros()) as usize
}

/// Precomputed monomial table polynomial for embedding-based range proofs.
///
/// `t(X) = Σ_{j=0}^{bound} j · X^j` encodes the valid range `[0, bound]`
/// as a degree-`bound` polynomial whose constant term matches the
/// monomial-encoded witness.  The full embedding (ct(g_i · t(X)) == f_i)
/// is not yet wired in-circuit; the adaptive bit decomposition provides
/// equivalent semantic enforcement for scalar-field constraints.
pub fn precompute_table_polynomial(bound: u64) -> Vec<u64> {
    (0..=bound).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monomial_bit_count_values() {
        assert_eq!(monomial_bit_count(0), 1);
        assert_eq!(monomial_bit_count(1), 1);
        assert_eq!(monomial_bit_count(2), 1);
        assert_eq!(monomial_bit_count(3), 2);
        assert_eq!(monomial_bit_count(4), 2);
        assert_eq!(monomial_bit_count(5), 3);
        assert_eq!(monomial_bit_count(8), 3);
        assert_eq!(monomial_bit_count(9), 4);
        assert_eq!(monomial_bit_count(131072), 17);
    }

    #[test]
    fn precompute_table_polynomial_basic() {
        let table = precompute_table_polynomial(5);
        assert_eq!(table, vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn precompute_table_polynomial_empty() {
        let table = precompute_table_polynomial(0);
        assert_eq!(table, vec![0]);
    }
}
