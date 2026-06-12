// Protocol constants shared across all Noir circuits.
//
// Q: RLWE ciphertext modulus (one of the RNS primes from the
//    production backend). Hardcoded per F1 backend lock -- NOT
//    prover-supplied.

pub global Q: Field = 288230376173076481;

// Domain separation tags for Poseidon hashing.
// Each tag prevents cross-context collision attacks.
pub global DOMAIN_VECTOR_MERKLE: Field = 1;
pub global DOMAIN_STATEMENT_BINDING: Field = 2;
pub global DOMAIN_CHALLENGE_DERIVE: Field = 3;
pub global DOMAIN_CIPHERTEXT_BINDING: Field = 4;
pub global DOMAIN_DKG_BINDING: Field = 5;
pub global DOMAIN_AGGREGATOR_D_COMMIT: Field = 6;
pub global DOMAIN_DKG_SHARE_COMMIT: Field = 7;
pub global DOMAIN_SZ_CHALLENGE: Field = 8;
pub global DOMAIN_AJTAI_COMMITMENT: Field = 9;
pub global DOMAIN_C2_ENCRYPTION_CHALLENGE: Field = 10;

// ── Ajtai commitment parameters (P4) ──────────────────────────────
// Ring degree φ = 256 (Z[X]/(X^256+1)).
pub global PHI: u32 = 256;
// Number of commitment rows m = 13 (output ring elements).
pub global M: u32 = 13;
// Commitment modulus q_commit = 562_949_953_438_721 ≈ 2^49.
pub global Q_COMMIT: Field = 562949953438721;
