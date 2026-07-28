//! Per-channel cyclotomic ring types for native LatticeFold+ folding over RNS primes.
//!
//! # Architecture
//!
//! Each RNS channel `q_l` of the BFV ciphertext modulus `Q = ∏ q_l` gets its own
//! cyclotomic ring `R_{q_l} = Z_{q_l}[X]/(X^N+1)` with dedicated NTT context.
//! Folding is performed natively over each ring — `mod q_l` and `mod X^N+1` are
//! free (ring equality), eliminating the GRECO quotient-witness overhead required
//! when emulating BFV arithmetic over a foreign field (BN254 in Noir circuits).
//!
//! An additional reconstruction track over a large prime `P > Q` handles the final
//! CRT reconstruction and plaintext decode, where the quotient witnesses cannot
//! be avoided (they are the core of the relation).
//!
//! # Ring degree
//!
//! Production: **N = 8192** (default). Fast-test: **N = 256** via `--features fast-ring-n256`.
//! Both modes share the same trait interface; only the concrete ring types differ.

#![deny(missing_docs)]
#![allow(clippy::needless_range_loop, clippy::type_complexity)]

pub mod channel;
pub mod params;
pub mod ring;

pub use channel::RnsChannels;
pub use params::{ChannelParams, ProdParams};
pub use ring::{FheMathRing, RqPoly};
