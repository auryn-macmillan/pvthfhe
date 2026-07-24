//! # ⚠️ INTENTIONALLY MINIMAL
//!
//! RNG façade introduced by R0.7. Sole purpose: re-export `rand::rngs::OsRng` and provide the `production_rng()` factory so all production callsites depend only on this crate, enforced by the `forbid::seeded_rng_outside_demo` lint. Intentionally trivial; expanding it would dilute the lint's surface.

pub use rand::rngs::OsRng;

/// Returns a fresh OS-seeded production RNG.
pub fn production_rng() -> OsRng {
    OsRng
}
