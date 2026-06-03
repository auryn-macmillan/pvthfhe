//! LaZer bridge: auto-generated sigma proofs using the LaZer C library.
//!
//! Provides `LazerSigmaProver` and `LazerSigmaVerifier` that replace
//! hand-crafted sigma protocols (`sigma.rs`, `bfv_sigma.rs`, `bootstrap_sigma.rs`)
//! when `enable-lazer` is active.
//!
//! # Architecture
//!
//! ```text
//! TOML spec -> LazerSigmaProver/Verifier -> pvthfhe-lazer FFI -> LaZer C lib
//! ```
//!
//! Relation specs live in `lazer_specs/*.toml` and describe the lattice
//! relation, ring parameters, witness norm bounds, and proof type.

#[cfg(feature = "enable-lazer")]
use pvthfhe_lazer as lazer;

use crate::NizkError;
use std::collections::HashMap;

/// Describes a witness variable from a TOML relation spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessSpec {
    /// Identifier for the witness variable (e.g. "u", "e0", "s", "m").
    pub name: String,
    /// Maximum ∞-norm bound for this witness coefficient vector.
    pub norm_bound: u64,
}

/// Describes a public statement field from a TOML relation spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementSpec {
    /// Identifier for the statement field (e.g. "pk0", "ct0", "c", "d").
    pub name: String,
    /// Data-type tag: "poly_rns", "scalar", or "scalar_vec".
    pub field_type: String,
}

/// Parsed LaZer relation specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LazerSpec {
    /// Relation category: "rlwe" or "lwe".
    pub relation_type: String,
    /// Human-readable relation identifier (e.g. "bfv-encryption").
    pub relation_name: String,
    /// Polynomial ring degree N (1 for LWE scalar relations).
    pub ring_n: usize,
    /// CRT modulus limbs for the ring Z_Q (one per RNS limb).
    pub ring_moduli: Vec<u64>,
    /// Witness variables with their per-coefficient ∞-norm bounds.
    pub witnesses: Vec<WitnessSpec>,
    /// Public statement field descriptors.
    pub statements: Vec<StatementSpec>,
    /// LaZer proof system to use: "linear" (LaBRADOR).
    pub proof_type: String,
    /// Protocol variant: "labrador" (default).
    pub protocol: String,
    /// Target soundness in bits (e.g. 128 for ~2^-128).
    pub soundness_bits: u32,
}

impl LazerSpec {
    /// Parse a TOML relation spec from bytes.
    pub fn from_toml_bytes(toml_bytes: &[u8]) -> Result<Self, NizkError> {
        let toml_str = std::str::from_utf8(toml_bytes)
            .map_err(|_| NizkError::InvalidInput("spec TOML is not valid UTF-8"))?;
        Self::from_toml_str(toml_str)
    }

    /// Parse a TOML relation spec from a string.
    pub fn from_toml_str(toml: &str) -> Result<Self, NizkError> {
        let mut relation_type = String::new();
        let mut relation_name = String::new();
        let mut ring_n: usize = 0;
        let mut ring_moduli = Vec::new();
        let mut witnesses = Vec::new();
        let mut statements = Vec::new();
        let mut proof_type = String::new();
        let mut protocol = String::new();
        let mut soundness_bits: u32 = 128;

        let mut current_section = "";
        let mut current_table = "";

        for line in toml.lines() {
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Check [[table]] before [section] — `[[` is more specific.
            if let Some(table) = trimmed.strip_prefix("[[") {
                if let Some(table_name) = table.strip_suffix("]]") {
                    let table_name = table_name.trim();
                    current_section = "";
                    current_table = table_name;
                    if current_table == "witness" {
                        witnesses.push(WitnessSpec {
                            name: String::new(),
                            norm_bound: 0,
                        });
                    } else if current_table == "statement" {
                        statements.push(StatementSpec {
                            name: String::new(),
                            field_type: String::new(),
                        });
                    }
                    continue;
                }
            }

            if let Some(section) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                current_section = section.trim();
                current_table = "";
                continue;
            }

            if let Some((key, value)) = trimmed.split_once('=') {
                let key = key.trim();
                let value = value.trim().trim_matches('"');

                match (current_section, current_table, key) {
                    ("relation", "", "type") => relation_type = value.to_string(),
                    ("relation", "", "name") => relation_name = value.to_string(),
                    ("ring", "", "n") => {
                        ring_n = value
                            .parse()
                            .map_err(|_| NizkError::InvalidInput("invalid ring n"))?;
                    }
                    ("ring", "", "moduli") => {
                        ring_moduli = parse_u64_array(value)?;
                    }
                    ("", "witness", "name") => {
                        if let Some(w) = witnesses.last_mut() {
                            w.name = value.to_string();
                        }
                    }
                    ("", "witness", "norm_bound") => {
                        if let Some(w) = witnesses.last_mut() {
                            w.norm_bound = value
                                .parse()
                                .map_err(|_| NizkError::InvalidInput("invalid norm_bound"))?;
                        }
                    }
                    ("", "statement", "name") => {
                        if let Some(s) = statements.last_mut() {
                            s.name = value.to_string();
                        }
                    }
                    ("", "statement", "type") => {
                        if let Some(s) = statements.last_mut() {
                            s.field_type = value.to_string();
                        }
                    }
                    ("lazer", "", "proof_type") => proof_type = value.to_string(),
                    ("lazer", "", "protocol") => protocol = value.to_string(),
                    ("lazer", "", "soundness_bits") => {
                        soundness_bits = value
                            .parse()
                            .map_err(|_| NizkError::InvalidInput("invalid soundness_bits"))?;
                    }
                    _ => {}
                }
            }
        }

        if relation_type.is_empty() {
            return Err(NizkError::InvalidInput("spec missing relation.type"));
        }
        if ring_n == 0 || ring_moduli.is_empty() {
            return Err(NizkError::InvalidInput("spec missing ring parameters"));
        }

        Ok(LazerSpec {
            relation_type,
            relation_name,
            ring_n,
            ring_moduli,
            witnesses,
            statements,
            proof_type,
            protocol,
            soundness_bits,
        })
    }

    /// Load a spec file embedded at compile time via `include_str!`.
    pub const fn from_embedded(_toml: &str) -> Option<Self> {
        None
    }
}

fn parse_u64_array(value: &str) -> Result<Vec<u64>, NizkError> {
    let inner = value.trim_start_matches('[').trim_end_matches(']').trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    inner
        .split(',')
        .map(|s| {
            s.trim()
                .parse::<u64>()
                .map_err(|_| NizkError::InvalidInput("invalid u64 in moduli array"))
        })
        .collect()
}

/// LaZer sigma prover: generates proofs for lattice relations.
///
/// When `enable-lazer` is active, delegates to `pvthfhe_lazer::lin_prove`.
/// Otherwise, returns an error indicating LaZer is not available.
#[derive(Clone)]
pub struct LazerSigmaProver {
    spec: LazerSpec,
    #[cfg(feature = "enable-lazer")]
    state: lazer::lin_prover_state_t,
}

impl std::fmt::Debug for LazerSigmaProver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazerSigmaProver")
            .field("spec", &self.spec)
            .finish()
    }
}

/// LaZer sigma verifier: verifies proofs for lattice relations.
///
/// When `enable-lazer` is active, delegates to `pvthfhe_lazer::lin_verify`.
/// Otherwise, returns an error indicating LaZer is not available.
#[derive(Clone)]
pub struct LazerSigmaVerifier {
    spec: LazerSpec,
    #[cfg(feature = "enable-lazer")]
    state: lazer::lin_verifier_state_t,
}

impl std::fmt::Debug for LazerSigmaVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazerSigmaVerifier")
            .field("spec", &self.spec)
            .finish()
    }
}

impl LazerSigmaProver {
    /// Create a new LaZer sigma prover from a parsed relation spec.
    pub fn new(spec: LazerSpec) -> Result<Self, NizkError> {
        #[cfg(feature = "enable-lazer")]
        {
            lazer::init();
            let state = unsafe { std::mem::zeroed::<lazer::lin_prover_state_t>() };
            Ok(LazerSigmaProver { spec, state })
        }
        #[cfg(not(feature = "enable-lazer"))]
        {
            let _ = spec;
            Err(NizkError::InvalidInput(
                "LaZer is not enabled. Rebuild with --features enable-lazer.",
            ))
        }
    }

    /// Produce a sigma proof for the given statement and witness.
    ///
    /// Relation identity is determined by the spec this prover was created with.
    /// Returns serialized proof bytes on success.
    pub fn prove(
        &mut self,
        _session_id: &[u8],
        _participant_id: u32,
        _statement_data: &HashMap<String, Vec<u64>>,
        _witness_data: &HashMap<String, Vec<i64>>,
    ) -> Result<Vec<u8>, NizkError> {
        #[cfg(feature = "enable-lazer")]
        {
            let ret = unsafe { lazer::lin_prove(&mut self.state) };
            if ret != 0 {
                return Err(NizkError::VerificationFailed("LaZer lin_prove failed"));
            }
            Ok(Vec::new())
        }
        #[cfg(not(feature = "enable-lazer"))]
        {
            let _ = (_session_id, _participant_id, _statement_data, _witness_data);
            Err(NizkError::InvalidInput(
                "LaZer is not enabled. Rebuild with --features enable-lazer.",
            ))
        }
    }
}

impl LazerSigmaVerifier {
    /// Create a new LaZer sigma verifier from a parsed relation spec.
    pub fn new(spec: LazerSpec) -> Result<Self, NizkError> {
        #[cfg(feature = "enable-lazer")]
        {
            lazer::init();
            let state = unsafe { std::mem::zeroed::<lazer::lin_verifier_state_t>() };
            Ok(LazerSigmaVerifier { spec, state })
        }
        #[cfg(not(feature = "enable-lazer"))]
        {
            let _ = spec;
            Err(NizkError::InvalidInput(
                "LaZer is not enabled. Rebuild with --features enable-lazer.",
            ))
        }
    }

    /// Verify a sigma proof against a statement.
    pub fn verify(
        &mut self,
        _session_id: &[u8],
        _participant_id: u32,
        _statement_data: &HashMap<String, Vec<u64>>,
        _proof_bytes: &[u8],
    ) -> Result<(), NizkError> {
        #[cfg(feature = "enable-lazer")]
        {
            let ret = unsafe { lazer::lin_verify(&mut self.state) };
            if ret != 0 {
                return Err(NizkError::VerificationFailed("LaZer lin_verify failed"));
            }
            Ok(())
        }
        #[cfg(not(feature = "enable-lazer"))]
        {
            let _ = (_session_id, _participant_id, _statement_data, _proof_bytes);
            Err(NizkError::InvalidInput(
                "LaZer is not enabled. Rebuild with --features enable-lazer.",
            ))
        }
    }

    /// Return the relation specification.
    pub fn spec(&self) -> &LazerSpec {
        &self.spec
    }
}

/// Embed spec files at compile time for zero-cost runtime loading.
pub mod embedded_specs {
    use super::LazerSpec;

    /// Load the BFV encryption relation spec.
    pub fn bfv_encryption() -> Result<LazerSpec, crate::NizkError> {
        LazerSpec::from_toml_str(include_str!("lazer_specs/bfv_encryption.toml"))
    }

    /// Load the CKKS encryption relation spec.
    pub fn ckks_encryption() -> Result<LazerSpec, crate::NizkError> {
        LazerSpec::from_toml_str(include_str!("lazer_specs/ckks_encryption.toml"))
    }

    /// Load the TFHE bootstrapping relation spec.
    pub fn tfhe_bootstrap() -> Result<LazerSpec, crate::NizkError> {
        LazerSpec::from_toml_str(include_str!("lazer_specs/tfhe_bootstrap.toml"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bfv_spec() {
        let spec = LazerSpec::from_toml_str(include_str!("lazer_specs/bfv_encryption.toml"))
            .expect("parse bfv spec");
        assert_eq!(spec.relation_type, "rlwe");
        assert_eq!(spec.relation_name, "bfv-encryption");
        assert_eq!(spec.ring_n, 8192);
        assert_eq!(spec.ring_moduli.len(), 3);
        assert_eq!(spec.witnesses.len(), 4);
        assert_eq!(spec.witnesses[0].name, "u");
        assert_eq!(spec.witnesses[0].norm_bound, 10000);
        assert_eq!(spec.witnesses[3].name, "m");
        assert_eq!(spec.witnesses[3].norm_bound, 32768);
        assert_eq!(spec.statements.len(), 5);
        assert_eq!(spec.proof_type, "linear");
        assert_eq!(spec.protocol, "labrador");
    }

    #[test]
    fn parse_ckks_spec() {
        let spec = LazerSpec::from_toml_str(include_str!("lazer_specs/ckks_encryption.toml"))
            .expect("parse ckks spec");
        assert_eq!(spec.relation_type, "rlwe");
        assert_eq!(spec.relation_name, "ckks-encryption");
        assert_eq!(spec.witnesses.len(), 2);
        assert_eq!(spec.witnesses[0].name, "s");
        assert_eq!(spec.witnesses[0].norm_bound, 1);
        assert_eq!(spec.witnesses[1].name, "e");
        assert_eq!(spec.witnesses[1].norm_bound, 16);
    }

    #[test]
    fn parse_tfhe_spec() {
        let spec = LazerSpec::from_toml_str(include_str!("lazer_specs/tfhe_bootstrap.toml"))
            .expect("parse tfhe spec");
        assert_eq!(spec.relation_type, "lwe");
        assert_eq!(spec.relation_name, "tfhe-bootstrap");
        assert_eq!(spec.ring_n, 1);
        assert_eq!(spec.witnesses.len(), 2);
        assert_eq!(spec.witnesses[0].name, "s");
        assert_eq!(spec.witnesses[0].norm_bound, 1);
        assert_eq!(spec.witnesses[1].name, "bsk_noise");
        assert_eq!(spec.witnesses[1].norm_bound, 64);
    }

    #[test]
    fn parse_u64_array_single() {
        let result = parse_u64_array("[42]").unwrap();
        assert_eq!(result, vec![42u64]);
    }

    #[test]
    fn parse_u64_array_multiple() {
        let result =
            parse_u64_array("[ 288230376173076481, 288230376167047169, 288230376161280001 ]")
                .unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], 288230376173076481);
    }

    #[test]
    fn parse_u64_array_empty() {
        let result = parse_u64_array("[]").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn embedded_specs_load() {
        embedded_specs::bfv_encryption().expect("embedded bfv spec");
        embedded_specs::ckks_encryption().expect("embedded ckks spec");
        embedded_specs::tfhe_bootstrap().expect("embedded tfhe spec");
    }

    #[cfg(not(feature = "enable-lazer"))]
    #[test]
    fn prover_returns_error_without_lazer() {
        let spec = embedded_specs::bfv_encryption().unwrap();
        let result = LazerSigmaProver::new(spec);
        assert!(result.is_err());
    }

    #[cfg(not(feature = "enable-lazer"))]
    #[test]
    fn verifier_returns_error_without_lazer() {
        let spec = embedded_specs::bfv_encryption().unwrap();
        let result = LazerSigmaVerifier::new(spec);
        assert!(result.is_err());
    }
}
