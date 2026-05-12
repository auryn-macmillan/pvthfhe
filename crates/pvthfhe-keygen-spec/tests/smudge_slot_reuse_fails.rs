#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use pvthfhe_keygen_spec::{SmudgeSlotError, SmudgeSlotPolicy, SmudgeSlotRegistry};
use serde_json;

// ---------------------------------------------------------------------------
// SmudgeSlotRegistry — slot reuse rejection
// ---------------------------------------------------------------------------

#[test]
fn consume_fresh_slot_succeeds() {
    let mut reg = SmudgeSlotRegistry::default();
    let result = reg.consume("s1", 0, 0);
    assert!(result.is_ok(), "fresh slot consumption should succeed");
    assert!(
        reg.is_consumed("s1", 0, 0),
        "just-consumed slot should be marked consumed"
    );
    assert!(
        !reg.is_fresh("s1", 0, 0),
        "just-consumed slot should not be fresh"
    );
}

#[test]
fn consume_same_slot_twice_fails() {
    let mut reg = SmudgeSlotRegistry::default();

    // First consumption succeeds.
    reg.consume("s1", 0, 0)
        .expect("first consumption should succeed");

    // Second consumption of the exact same slot must fail.
    let err = reg
        .consume("s1", 0, 0)
        .expect_err("reconsuming the same slot should fail");

    match &err {
        SmudgeSlotError::SlotAlreadyConsumed {
            session_id,
            party_id,
            slot_index,
        } => {
            assert_eq!(session_id, "s1");
            assert_eq!(*party_id, 0);
            assert_eq!(*slot_index, 0);
        }
    }

    // Error message should contain the identifiers.
    let msg = err.to_string();
    assert!(
        msg.contains("s1"),
        "error message should contain session_id"
    );
    assert!(
        msg.contains("party=0"),
        "error message should contain party_id"
    );
    assert!(
        msg.contains("slot=0"),
        "error message should contain slot_index"
    );
}

#[test]
fn different_party_same_slot_succeeds() {
    let mut reg = SmudgeSlotRegistry::default();

    reg.consume("s1", 0, 0).expect("party 0 slot 0");

    // Same slot index, different party — should be independent.
    let result = reg.consume("s1", 1, 0);
    assert!(result.is_ok(), "different party should be a fresh slot");
    assert!(reg.is_consumed("s1", 0, 0));
    assert!(reg.is_consumed("s1", 1, 0));
}

#[test]
fn different_slot_same_party_succeeds() {
    let mut reg = SmudgeSlotRegistry::default();

    reg.consume("s1", 0, 0).expect("slot 0");

    // Different slot index, same party — should be independent.
    let result = reg.consume("s1", 0, 1);
    assert!(
        result.is_ok(),
        "different slot index should be a fresh slot"
    );
    assert!(reg.is_consumed("s1", 0, 0));
    assert!(reg.is_consumed("s1", 0, 1));
}

#[test]
fn cross_session_isolation() {
    let mut reg = SmudgeSlotRegistry::default();

    // Consume in session A.
    reg.consume("session_a", 0, 0).expect("session A slot 0");

    // Same (party, slot) in session B must be fresh.
    assert!(
        reg.is_fresh("session_b", 0, 0),
        "same party/slot in a different session should be fresh"
    );
    let result = reg.consume("session_b", 0, 0);
    assert!(
        result.is_ok(),
        "cross-session isolation: different sessions should not collide"
    );

    assert!(reg.is_consumed("session_a", 0, 0));
    assert!(reg.is_consumed("session_b", 0, 0));
}

#[test]
fn is_fresh_and_is_consumed_are_consistent() {
    let mut reg = SmudgeSlotRegistry::default();

    // Before any consumption.
    assert!(reg.is_fresh("s1", 0, 0));
    assert!(!reg.is_consumed("s1", 0, 0));

    // After consumption.
    reg.consume("s1", 0, 0).expect("consume");
    assert!(!reg.is_fresh("s1", 0, 0));
    assert!(reg.is_consumed("s1", 0, 0));

    // A different slot is still fresh.
    assert!(reg.is_fresh("s1", 0, 1));
    assert!(!reg.is_consumed("s1", 0, 1));
}

#[test]
fn registry_default_is_empty() {
    let reg = SmudgeSlotRegistry::default();
    assert!(reg.is_fresh("any_session", 42, 99));
    assert!(!reg.is_consumed("any_session", 42, 99));
}

// ---------------------------------------------------------------------------
// SmudgeSlotPolicy — serialization roundtrip and invariants
// ---------------------------------------------------------------------------

#[test]
fn smudge_slot_policy_serde_roundtrip() {
    use pvthfhe_keygen_spec::HexBlob;

    let policy = SmudgeSlotPolicy {
        slots_per_party: 16,
        pre_generated: true,
        policy_hash: HexBlob(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
        ),
    };

    let json = serde_json::to_string_pretty(&policy).expect("serialize");
    let roundtripped: SmudgeSlotPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(policy, roundtripped);
}

#[test]
fn smudge_slot_policy_on_demand() {
    use pvthfhe_keygen_spec::HexBlob;

    let policy = SmudgeSlotPolicy {
        slots_per_party: 1,
        pre_generated: false,
        policy_hash: HexBlob("00".to_string()),
    };

    assert!(!policy.pre_generated);
    assert_eq!(policy.slots_per_party, 1);

    let json = serde_json::to_string_pretty(&policy).expect("serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse as generic JSON");
    assert_eq!(parsed["pre_generated"], false);
    assert_eq!(parsed["slots_per_party"], 1);
}
