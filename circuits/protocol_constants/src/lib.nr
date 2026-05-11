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
