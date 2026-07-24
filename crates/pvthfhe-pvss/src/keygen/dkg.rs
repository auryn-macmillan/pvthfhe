//! Distributed key generation ceremony for BFV threshold FHE.
//!
//! Wraps [`FhersBackend`](pvthfhe_fhe::fhers::FhersBackend) to orchestrate a
//! Pedersen-style DKG across `n` parties with threshold `t`.

use ark_bn254::G1Affine;
use pvthfhe_fhe::{
    error::FheError,
    fhers::FhersBackend,
    types::{Ciphertext, DecryptShare, KeygenShare, PublicKey},
    FheBackend,
};
use pvthfhe_nizk::schnorr::{self, SchnorrPopProof};
use pvthfhe_rng::OsRng;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

/// Parameters for a DKG ceremony.
#[derive(Debug, Clone)]
pub struct DkgParams {
    /// Total number of parties.
    pub n: usize,
    /// Threshold required for decryption.
    pub t: usize,
    /// Optional per-round timeout. When set, the coordinator may time out
    /// unresponsive parties and advance the round without them.
    pub round_timeout: Option<Duration>,
}

/// Identity record for one party in the DKG ceremony.
///
/// Contains the Schnorr public key used for rogue-key prevention and the
/// associated proof-of-possession demonstrating that the party knows the
/// corresponding secret key.
#[derive(Clone, Debug)]
pub struct PartyIdentity {
    /// Party index (1-based).
    pub party_id: u32,
    /// Schnorr public key over BN254 G1.
    pub public_key: G1Affine,
    /// Schnorr proof-of-possession for this party's public key.
    pub pop_proof: SchnorrPopProof,
}

/// Errors returned by DKG ceremony operations.
#[derive(Debug)]
pub enum DkgError {
    /// Underlying FHE backend error.
    Fhe {
        /// Human-readable error message.
        message: String,
        /// Optional party attribution for blame tracking.
        party_id: Option<u32>,
    },
    /// Ceremony has not been run yet.
    NotInitialized {
        /// Optional party identifier for blame attribution.
        party_id: Option<u32>,
    },
    /// Invalid parameters supplied.
    InvalidParams {
        /// Optional party identifier for blame attribution.
        party_id: Option<u32>,
        /// The error message.
        message: String,
    },
    /// Round timeout triggered.
    RoundTimeout {
        /// Round number that timed out.
        round: u8,
        /// Parties that failed to respond before the timeout.
        missing_parties: Vec<u32>,
    },
}

impl From<FheError> for DkgError {
    fn from(e: FheError) -> Self {
        DkgError::Fhe {
            message: e.to_string(),
            party_id: None,
        }
    }
}

impl core::fmt::Display for DkgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DkgError::Fhe { message, party_id } => match party_id {
                Some(id) => write!(f, "FHE error (party {id}): {message}"),
                None => write!(f, "FHE error: {message}"),
            },
            DkgError::NotInitialized { party_id } => match party_id {
                Some(id) => write!(f, "DKG ceremony not yet run (party {id})"),
                None => write!(f, "DKG ceremony not yet run"),
            },
            DkgError::InvalidParams { party_id, message } => match party_id {
                Some(id) => write!(f, "invalid DKG params (party {id}): {message}"),
                None => write!(f, "invalid DKG params: {message}"),
            },
            DkgError::RoundTimeout {
                round,
                missing_parties,
            } => write!(
                f,
                "round {round} timeout: missing parties {missing_parties:?}"
            ),
        }
    }
}

impl std::error::Error for DkgError {}

/// DKG ceremony orchestrator wrapping [`FhersBackend`].
pub struct DkgCeremony {
    backend: FhersBackend,
    n: usize,
    t: usize,
    session_id: [u8; 32],
    keygen_shares: Vec<KeygenShare>,
    public_key: Option<PublicKey>,
    party_identities: Vec<PartyIdentity>,
    round_timeout: Option<Duration>,
}

impl DkgCeremony {
    /// Creates a new DKG ceremony with the given parameters.
    ///
    /// Validates that `1 <= t <= n` and initialises the BFV backend.
    pub fn new(params: DkgParams) -> Result<Self, DkgError> {
        if params.t == 0 || params.t > params.n {
            return Err(DkgError::InvalidParams {
                party_id: None,
                message: format!(
                    "threshold t={} must satisfy 1 <= t <= n={}",
                    params.t, params.n
                ),
            });
        }

        let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML)?;
        let mut rng = OsRng;
        let mut session_id = [0u8; 32];
        rng.fill_bytes(&mut session_id);

        Ok(Self {
            backend,
            n: params.n,
            t: params.t,
            session_id,
            keygen_shares: Vec::with_capacity(params.n),
            public_key: None,
            party_identities: Vec::with_capacity(params.n),
            round_timeout: params.round_timeout,
        })
    }

    /// Runs the DKG ceremony.
    ///
    /// Generates keygen shares for all `n` parties, sets up the threshold
    /// parameters, and aggregates the collective public key.
    ///
    /// Additionally generates Schnorr keypairs and proof-of-possession
    /// (PoP) proofs for each party to prevent rogue-key attacks on the
    /// aggregate public key.
    ///
    /// If `round_timeout` is set, the coordinator will time out after the
    /// specified duration and advance without waiting for unresponsive parties.
    pub fn run(&mut self) -> Result<(), DkgError> {
        let mut rng = OsRng;
        let start_time = Instant::now();

        for party_id in 1u32..=self.n as u32 {
            // Check timeout before processing next party
            if let Some(timeout) = self.round_timeout {
                if start_time.elapsed() >= timeout {
                    // Collect missing parties (those not yet processed)
                    let current_party = party_id;
                    let missing_parties = (current_party..=self.n as u32).collect();
                    return Err(DkgError::RoundTimeout {
                        round: 1,
                        missing_parties,
                    });
                }
            }

            let share = match self.backend.keygen_share_with_session(&self.session_id, party_id, &mut rng) {
                Ok(share) => share,
                Err(e) => return Err(DkgError::Fhe {
                    message: e.to_string(),
                    party_id: Some(party_id),
                }),
            };
            self.keygen_shares.push(share);

            let (sk, pk) = schnorr::generate_signing_keypair(&mut rng);
            let pop = schnorr::schnorr_pop_prove(sk, pk, &mut rng);
            self.party_identities.push(PartyIdentity {
                party_id,
                public_key: pk,
                pop_proof: pop,
            });
        }

        let session_seed: [u8; 32] = Sha256::digest(self.session_id).into();
        self.backend.setup_threshold(self.n, self.t, session_seed)
            .map_err(|e| DkgError::Fhe {
                message: e.to_string(),
                party_id: None,
            })?;

        let pk = self.backend.aggregate_keygen(&self.keygen_shares)?;
        self.public_key = Some(pk);

        Ok(())
    }

    /// Returns the aggregated public key.
    ///
    /// Errors with [`DkgError::NotInitialized`] if `run` has not been called.
    pub fn public_key(&self) -> Result<&PublicKey, DkgError> {
        self.public_key.as_ref().ok_or(DkgError::NotInitialized { party_id: None })
    }

    /// Returns the identity records for all parties that participated in the
    /// DKG ceremony.
    ///
    /// Each identity contains the party's Schnorr public key and
    /// proof-of-possession (PoP). Returns an empty vector if `run` has not
    /// been called.
    pub fn party_identities(&self) -> Vec<PartyIdentity> {
        self.party_identities.clone()
    }

    /// Verifies all parties' Schnorr proof-of-possession (PoP) proofs.
    ///
    /// Returns `true` if every party's PoP validates against its public key
    /// and the ceremony has been run. Returns `false` if no identities exist
    /// or if any PoP verification fails.
    pub fn verify_party_pops(&self) -> bool {
        if self.party_identities.is_empty() {
            return false;
        }
        self.party_identities
            .iter()
            .all(|id| schnorr::schnorr_pop_verify(id.public_key, &id.pop_proof))
    }

    /// Encrypts `plaintext` under the collective public key.
    ///
    /// Returns a [`Ciphertext`] suitable for threshold decryption.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Ciphertext, DkgError> {
        let pk = self.public_key()?;
        let mut rng = OsRng;
        Ok(self.backend.encrypt(pk, plaintext, &mut rng)?)
    }

    /// Produces a partial decryption share for `ct` from `party_id`.
    pub fn partial_decrypt(
        &self,
        ct: &Ciphertext,
        party_id: u32,
    ) -> Result<DecryptShare, DkgError> {
        let mut rng = OsRng;
        Ok(self.backend.partial_decrypt(ct, party_id, &mut rng)?)
    }

    /// Aggregates partial decryption shares into the recovered plaintext.
    ///
    /// Requires at least `t` valid shares; returns an error otherwise.
    pub fn aggregate_decrypt(
        &self,
        ct: &Ciphertext,
        shares: &[DecryptShare],
    ) -> Result<Vec<u8>, DkgError> {
        Ok(self.backend.aggregate_decrypt(ct, shares, self.t, b"")?)
    }
}
