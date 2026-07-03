//! Public batched Shamir/RS share-computation checker for two-track DKG.
//!
//! This module is intentionally independent of the D.1 share-encryption proof
//! verifier.  It checks the public transcript-validity relation for dealer
//! share vectors: one `sk` track and one or more `e_sm` smudge-slot tracks are
//! evaluations of bounded low-degree BN254 Shamir polynomials whose constant
//! terms match transcript-bound public commitments.

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField, Zero};
use pvthfhe_types::ProtocolBytes;
use sha2::{Digest, Sha256};

const DIGEST_LEN: usize = 32;

/// One public Shamir/RS share evaluation over the BN254 scalar field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldShare {
    /// One-based recipient/evaluation index.
    pub recipient_index: u16,
    /// Public field value claimed for this recipient.
    pub value: Fr,
}

/// Public share-computation track for threshold secret-key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareComputationTrack {
    /// Ordered share evaluations published by the dealer.
    pub shares: Vec<FieldShare>,
    /// Commitment to the polynomial constant term for this track.
    pub secret_commitment: [u8; DIGEST_LEN],
}

/// Public share-computation track for one committed smudging-noise slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ESmShareComputationSlot {
    /// Smudge slot/batch index bound into the relation.
    pub slot_index: u16,
    /// Ordered share evaluations published by the dealer for this slot.
    pub shares: Vec<FieldShare>,
    /// Commitment to this slot polynomial's constant term.
    pub smudge_commitment: [u8; DIGEST_LEN],
}

/// Batched public statement for the E.1 `sk` + `e_sm` share-computation relation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchedShareComputationStatement {
    /// Session binding bytes.
    pub session_id: ProtocolBytes,
    /// DKG transcript/anchor root binding this relation to one DKG session.
    pub dkg_root: ProtocolBytes,
    /// Dealer whose polynomial evaluations are checked.
    pub dealer_id: u16,
    /// Maximum allowed polynomial degree.
    pub max_degree: usize,
    /// Inclusive signed coefficient bound.  Coefficients are interpreted by the
    /// smaller of their canonical representative and its negation.
    pub coefficient_bound: u64,
    /// Threshold secret-key share-computation track.
    pub sk: ShareComputationTrack,
    /// Smudging-noise share-computation tracks, one per slot.
    pub esm_slots: Vec<ESmShareComputationSlot>,
}

/// Successful public relation check plus foldable public instance digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedBatchedShareComputation {
    /// Deterministic public instance commitment suitable for later folding.
    pub public_instance_commitment: [u8; DIGEST_LEN],
    /// Interpolated `sk` coefficients, low-to-high degree.
    pub sk_coefficients: Vec<Fr>,
    /// Interpolated `e_sm` coefficients by slot, low-to-high degree.
    pub esm_coefficients: Vec<(u16, Vec<Fr>)>,
}

/// Error returned by the public share-computation checker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShareComputationError {
    /// Statement metadata is malformed.
    InvalidStatement { dealer_id: u16, message: &'static str },
    /// A track contains malformed share coordinates.
    InvalidShareVector { dealer_id: u16, message: &'static str },
    /// A track is not a Reed-Solomon codeword for the configured degree.
    NonLowDegree {
        /// The dealer whose shares failed the RS check.
        dealer_id: u16,
        /// Track label that failed the RS parity/low-degree check.
        track: String,
    },
    /// Interpolated constant term does not match the public commitment.
    CommitmentMismatch {
        /// The dealer whose commitment mismatched.
        dealer_id: u16,
        /// Track label whose constant-term commitment mismatched.
        track: String,
    },
    /// A coefficient exceeds the configured signed bound.
    CoefficientBound {
        /// The dealer whose coefficient exceeded the bound.
        dealer_id: u16,
        /// Track label with a coefficient outside the configured bound.
        track: String,
    },
}

impl core::fmt::Display for ShareComputationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidStatement { dealer_id, message } => {
                write!(f, "invalid share-computation statement from dealer {dealer_id}: {message}")
            }
            Self::InvalidShareVector { dealer_id, message } => {
                write!(f, "invalid share vector from dealer {dealer_id}: {message}")
            }
            Self::NonLowDegree { dealer_id, track } => {
                write!(f, "dealer {dealer_id} shares for {track} are not low-degree Shamir/RS evaluations")
            }
            Self::CommitmentMismatch { dealer_id, track } => {
                write!(f, "dealer {dealer_id} {track} secret commitment mismatch")
            }
            Self::CoefficientBound { dealer_id, track } => {
                write!(f, "dealer {dealer_id} {track} coefficient bound exceeded")
            }
        }
    }
}

impl std::error::Error for ShareComputationError {}

/// Compute the public commitment to a dealer's `sk` polynomial constant term.
pub fn compute_sk_secret_commitment(
    session_id: &[u8],
    dkg_root: &[u8],
    dealer_id: u16,
    secret: Fr,
) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(b"pvthfhe-share-computation-sk-commitment-v1");
    h.update(session_id);
    h.update(dkg_root);
    h.update(dealer_id.to_be_bytes());
    h.update(b"sk");
    h.update(fr_bytes(&secret));
    h.finalize().into()
}

/// Compute the public commitment to a dealer's `e_sm` slot polynomial constant term.
pub fn compute_esm_secret_commitment(
    session_id: &[u8],
    dkg_root: &[u8],
    dealer_id: u16,
    slot_index: u16,
    secret: Fr,
) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(b"pvthfhe-share-computation-esm-commitment-v1");
    h.update(session_id);
    h.update(dkg_root);
    h.update(dealer_id.to_be_bytes());
    h.update(b"e_sm");
    h.update(slot_index.to_be_bytes());
    h.update(fr_bytes(&secret));
    h.finalize().into()
}

/// Verify the batched two-track public share-computation relation.
pub fn verify_batched_share_computation(
    statement: &BatchedShareComputationStatement,
) -> Result<CheckedBatchedShareComputation, ShareComputationError> {
    validate_statement(statement, statement.dealer_id)?;

    let sk_coefficients = check_track(
        "sk",
        &statement.sk.shares,
        statement.max_degree,
        statement.coefficient_bound,
        statement.dealer_id,
    )?;
    let expected_sk = compute_sk_secret_commitment(
        &statement.session_id,
        &statement.dkg_root,
        statement.dealer_id,
        sk_coefficients[0],
    );
    if expected_sk != statement.sk.secret_commitment {
        return Err(ShareComputationError::CommitmentMismatch {
            dealer_id: statement.dealer_id,
            track: "sk".to_owned(),
        });
    }

    let mut seen_slots = Vec::with_capacity(statement.esm_slots.len());
    let mut esm_coefficients = Vec::with_capacity(statement.esm_slots.len());
    for slot in &statement.esm_slots {
        if seen_slots.contains(&slot.slot_index) {
            return Err(ShareComputationError::InvalidStatement {
                dealer_id: statement.dealer_id,
                message: "duplicate e_sm slot",
            });
        }
        seen_slots.push(slot.slot_index);
        let track_name = format!("e_sm slot {}", slot.slot_index);
        let coeffs = check_track(
            &track_name,
            &slot.shares,
            statement.max_degree,
            statement.coefficient_bound,
            statement.dealer_id,
        )?;
        let expected = compute_esm_secret_commitment(
            &statement.session_id,
            &statement.dkg_root,
            statement.dealer_id,
            slot.slot_index,
            coeffs[0],
        );
        if expected != slot.smudge_commitment {
            return Err(ShareComputationError::CommitmentMismatch {
                dealer_id: statement.dealer_id,
                track: track_name,
            });
        }
        esm_coefficients.push((slot.slot_index, coeffs));
    }

    Ok(CheckedBatchedShareComputation {
        public_instance_commitment: compute_public_instance_commitment(statement),
        sk_coefficients,
        esm_coefficients,
    })
}

fn validate_statement(
    statement: &BatchedShareComputationStatement,
    dealer_id: u16,
) -> Result<(), ShareComputationError> {
    if statement.session_id.is_empty() {
        return Err(ShareComputationError::InvalidStatement {
            dealer_id,
            message: "empty session_id",
        });
    }
    if statement.dkg_root.is_empty() {
        return Err(ShareComputationError::InvalidStatement {
            dealer_id,
            message: "empty dkg_root",
        });
    }
    if statement.esm_slots.is_empty() {
        return Err(ShareComputationError::InvalidStatement {
            dealer_id,
            message: "missing e_sm slots",
        });
    }
    if statement.max_degree == usize::MAX {
        return Err(ShareComputationError::InvalidStatement {
            dealer_id,
            message: "max_degree overflow",
        });
    }
    Ok(())
}

fn check_track(
    track: &str,
    shares: &[FieldShare],
    max_degree: usize,
    coefficient_bound: u64,
    dealer_id: u16,
) -> Result<Vec<Fr>, ShareComputationError> {
    let min_points = max_degree
        .checked_add(1)
        .ok_or(ShareComputationError::InvalidStatement {
            dealer_id,
            message: "degree overflow",
        })?;
    if shares.len() <= min_points {
        return Err(ShareComputationError::InvalidShareVector {
            dealer_id,
            message: "insufficient parity shares",
        });
    }
    validate_share_coordinates(track, shares, dealer_id)?;

    let interpolation_points: Vec<(Fr, Fr)> = shares
        .iter()
        .take(min_points)
        .map(|share| (Fr::from(u64::from(share.recipient_index)), share.value))
        .collect();
    let coefficients = interpolate_coefficients(&interpolation_points, dealer_id)?;

    for share in shares {
        let x = Fr::from(u64::from(share.recipient_index));
        if eval_bn254_poly(&coefficients, x) != share.value {
            return Err(ShareComputationError::NonLowDegree {
                dealer_id,
                track: track.to_owned(),
            });
        }
    }

    if coefficients
        .iter()
        .any(|coeff| !coefficient_within_signed_bound(coeff, coefficient_bound))
    {
        return Err(ShareComputationError::CoefficientBound {
            dealer_id,
            track: track.to_owned(),
        });
    }

    Ok(coefficients)
}

fn validate_share_coordinates(
    track: &str,
    shares: &[FieldShare],
    dealer_id: u16,
) -> Result<(), ShareComputationError> {
    let mut seen = Vec::with_capacity(shares.len());
    for share in shares {
        if share.recipient_index == 0 || seen.contains(&share.recipient_index) {
            return Err(ShareComputationError::InvalidShareVector {
                dealer_id,
                message: if track == "sk" { "sk" } else { "e_sm" },
            });
        }
        seen.push(share.recipient_index);
    }
    Ok(())
}

pub fn interpolate_coefficients(
    points: &[(Fr, Fr)],
    dealer_id: u16,
) -> Result<Vec<Fr>, ShareComputationError> {
    let degree = points.len() - 1;
    let mut coefficients = vec![Fr::ZERO; degree + 1];

    for (i, (x_i, y_i)) in points.iter().enumerate() {
        let mut basis = vec![Fr::ONE];
        let mut denominator = Fr::ONE;
        for (j, (x_j, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            denominator *= *x_i - *x_j;
            basis = multiply_by_linear(&basis, -*x_j, Fr::ONE);
        }
        let inv = denominator
            .inverse()
            .ok_or(ShareComputationError::InvalidShareVector {
                dealer_id,
                message: "duplicate x",
            })?;
        let scale = *y_i * inv;
        for (index, coeff) in basis.iter().enumerate() {
            coefficients[index] += *coeff * scale;
        }
    }

    Ok(coefficients)
}

fn multiply_by_linear(poly: &[Fr], constant: Fr, linear: Fr) -> Vec<Fr> {
    let mut out = vec![Fr::ZERO; poly.len() + 1];
    for (index, coeff) in poly.iter().enumerate() {
        out[index] += *coeff * constant;
        out[index + 1] += *coeff * linear;
    }
    out
}

fn eval_bn254_poly(coefficients: &[Fr], x: Fr) -> Fr {
    coefficients
        .iter()
        .rev()
        .fold(Fr::ZERO, |acc, coeff| acc * x + coeff)
}

fn coefficient_within_signed_bound(value: &Fr, bound: u64) -> bool {
    if bound == u64::MAX {
        return true;
    }
    value.is_zero()
        || canonical_u64(value).is_some_and(|v| v <= bound)
        || canonical_u64(&(-*value)).is_some_and(|v| v <= bound)
}

fn canonical_u64(value: &Fr) -> Option<u64> {
    let bigint = value.into_bigint();
    let limbs = bigint.as_ref();
    if limbs.iter().skip(1).all(|limb| *limb == 0) {
        Some(limbs[0])
    } else {
        None
    }
}

fn compute_public_instance_commitment(
    statement: &BatchedShareComputationStatement,
) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(b"pvthfhe-share-computation-public-instance-v1");
    h.update(statement.session_id.as_slice());
    h.update(statement.dkg_root.as_slice());
    h.update(statement.dealer_id.to_be_bytes());
    h.update((statement.max_degree as u64).to_be_bytes());
    h.update(statement.coefficient_bound.to_be_bytes());
    h.update(b"sk");
    hash_track(
        &mut h,
        &statement.sk.shares,
        &statement.sk.secret_commitment,
    );
    h.update((statement.esm_slots.len() as u64).to_be_bytes());
    for slot in &statement.esm_slots {
        h.update(b"e_sm");
        h.update(slot.slot_index.to_be_bytes());
        hash_track(&mut h, &slot.shares, &slot.smudge_commitment);
    }
    h.finalize().into()
}

fn hash_track(h: &mut Sha256, shares: &[FieldShare], commitment: &[u8; DIGEST_LEN]) {
    h.update(commitment);
    h.update((shares.len() as u64).to_be_bytes());
    for share in shares {
        h.update(share.recipient_index.to_be_bytes());
        h.update(fr_bytes(&share.value));
    }
}

fn fr_bytes(value: &Fr) -> Vec<u8> {
    value.into_bigint().to_bytes_le()
}
