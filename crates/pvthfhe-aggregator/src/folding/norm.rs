use crate::folding::ring_element::RingElement;
use ark_ff::PrimeField;

/// Enforce that a ring element's infinity norm is ≤ bound.
/// Returns Err if any coefficient exceeds the bound.
pub fn enforce_norm_inf<F: PrimeField>(
    element: &RingElement<F>,
    bound: F,
    label: &str,
) -> Result<(), String> {
    if element.is_empty() {
        return Ok(());
    }
    let norm = element.norm_inf();
    if norm > bound {
        return Err(format!("{} norm {} exceeds bound {}", label, norm, bound));
    }
    Ok(())
}

/// Validate a Cyclo folding witness:
/// - ‖s‖_∞ ≤ B (secret key)
/// - ‖e‖_∞ ≤ B_e (error)
/// - ‖z_s‖_∞ ≤ B_z (response)
/// - ‖z_e‖_∞ ≤ B_z (response)
pub fn validate_folding_witness<F: PrimeField>(
    s: &RingElement<F>,
    e: &RingElement<F>,
    z_s: &RingElement<F>,
    z_e: &RingElement<F>,
    b: F,
    b_e: F,
    b_z: F,
) -> Result<(), String> {
    enforce_norm_inf(s, b, "s")?;
    enforce_norm_inf(e, b_e, "e")?;
    enforce_norm_inf(z_s, b_z, "z_s")?;
    enforce_norm_inf(z_e, b_z, "z_e")?;
    Ok(())
}
