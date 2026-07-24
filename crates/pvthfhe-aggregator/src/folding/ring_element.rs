//! Re-export of the canonical generic ring element.
//!
//! The implementation lives in [`pvthfhe_cyclo::ring_element`] (cyclo is the
//! canonical home for lattice ring primitives — Phase 3.4 of the 2026-07-24
//! repo refactor). On the shared domain `F = F_{q_commit}` it agrees
//! coefficient-by-coefficient with [`pvthfhe_cyclo::ring`]; the equivalence is
//! pinned by `tests/primitive_equivalence.rs`.

pub use pvthfhe_cyclo::ring_element::RingElement;
