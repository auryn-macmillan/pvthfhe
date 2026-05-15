//! Smudge-slot freshness enforcement (F.2).
//!
//! Prevents reuse of smudge-noise commitment slots across decryption rounds.
//! Each `(session_id, party_id, slot_id)` tuple may only be used once per
//! session.  Reuse would leak information by revealing the same smudging noise
//! in two different decryption contexts.
//!
//! NOTE (C.3): The SmudgeSlotRegistry has a dual implementation — the
//! in-process `HashSet`-based variant here, and a separate counterpart in
//! `pvthfhe-fhe` for certain FHE flows.  The two should be consolidated into a
//! single canonical implementation during the next refactoring cycle (planned
//! as part of the interface-hardening milestone).

use std::collections::HashSet;

use crate::PvssError;

/// Tracks `(session_id, party_id, slot_id)` usage across a decryption session.
///
/// This is a simple in-memory research-prototype registry.  In a production
/// setting this would be replaced by a persistent, auditable store.
pub struct SmudgeSlotRegistry {
    used: HashSet<(Vec<u8>, u16, u16)>,
}

impl SmudgeSlotRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            used: HashSet::new(),
        }
    }

    /// Check whether `(session_id, party_id, slot_id)` has been used.
    ///
    /// If not, record it and return `Ok`.  If it has been used before, return
    /// [`PvssError::SmudgeSlotReused`].
    pub fn check_and_record(
        &mut self,
        session_id: &[u8],
        party_id: u16,
        slot_id: u16,
    ) -> Result<(), PvssError> {
        let key = (session_id.to_vec(), party_id, slot_id);
        if self.used.contains(&key) {
            return Err(PvssError::SmudgeSlotReused { party_id, slot_id });
        }
        self.used.insert(key);
        Ok(())
    }

    /// Return the number of slots currently recorded.
    pub fn len(&self) -> usize {
        self.used.len()
    }

    /// Return whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.used.is_empty()
    }
}

impl Default for SmudgeSlotRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_registry_is_empty() {
        let reg = SmudgeSlotRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn first_use_succeeds() {
        let mut reg = SmudgeSlotRegistry::new();
        assert!(reg.check_and_record(b"session-1", 1, 1).is_ok());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn reuse_is_rejected() {
        let mut reg = SmudgeSlotRegistry::new();
        reg.check_and_record(b"session-1", 1, 1).unwrap();
        let err = reg.check_and_record(b"session-1", 1, 1).unwrap_err();
        assert!(matches!(err, PvssError::SmudgeSlotReused { .. }));
    }
}
