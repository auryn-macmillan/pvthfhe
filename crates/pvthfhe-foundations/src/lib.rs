//! Foundational modules shared by every PVTHFHE crate.
//!
//! This crate merges the four former leaf crates `pvthfhe-types`,
//! `pvthfhe-rng`, `pvthfhe-wire`, and `pvthfhe-domain-tags` into a single
//! dependency-graph root. Each former crate is preserved verbatim as one
//! module with its public API intact, one level deeper:
//!
//! - [`types`]: shared byte-classification newtypes for protocol boundaries
//!   (`Secret`, `ShareSecret`, `Sk`, `NoisePoly`, `EncRandomness`,
//!   `CcsWitnessSecret`, `ProtocolBytes`, the encryption/decryption witness
//!   structs, and the BFV parameter preset), plus the canonical
//!   verification-statement TLV encoding / Poseidon-BN254 hash
//!   ([`types::verification_statement`]) and the witness-statement schema
//!   ([`types::witness_language`]).
//! - [`rng`]: ⚠️ INTENTIONALLY MINIMAL RNG façade introduced by R0.7. Sole
//!   purpose: re-export `rand::rngs::OsRng` and provide the
//!   `production_rng()` factory so all production callsites depend only on
//!   this module, enforced by the `forbid::seeded_rng_outside_demo` lint.
//!   Intentionally trivial; expanding it would dilute the lint's surface.
//! - [`wire`]: canonical versioned, length-prefixed wire envelope
//!   (`WireFormat`) for PVTHFHE adapters (phase R0.5).
//! - [`domain_tags`]: single source of truth for all `pvthfhe/...`
//!   domain-separation tags (R0.4). Adding a new tag requires a `Tag`
//!   variant + match arms in `as_bytes` and `all_literals`; callsites use
//!   `Tag::<Variant>.as_bytes()` (no raw `pvthfhe/...` literals), enforced
//!   by `lints/forbid_raw_pvthfhe_domain_tag.sh`.

pub mod domain_tags;
pub mod rng;
pub mod types;
pub mod wire;
