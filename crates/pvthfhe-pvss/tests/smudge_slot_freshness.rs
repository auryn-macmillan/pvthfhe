use pvthfhe_pvss::slot_registry::SmudgeSlotRegistry;
use pvthfhe_pvss::PvssError;

#[test]
fn reuse_same_slot_rejected() {
    let mut reg = SmudgeSlotRegistry::new();
    let session_id = b"session-alpha";

    reg.check_and_record(session_id, 1, 7).unwrap();

    let result = reg.check_and_record(session_id, 1, 7);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        PvssError::SmudgeSlotReused {
            party_id: 1,
            slot_id: 7,
        }
    ));
}

#[test]
fn different_party_same_slot_allowed() {
    let mut reg = SmudgeSlotRegistry::new();
    let session_id = b"session-beta";

    reg.check_and_record(session_id, 1, 3).unwrap();
    let result = reg.check_and_record(session_id, 2, 3);
    assert!(result.is_ok());
    assert_eq!(reg.len(), 2);
}

#[test]
fn different_slot_same_party_allowed() {
    let mut reg = SmudgeSlotRegistry::new();
    let session_id = b"session-gamma";

    reg.check_and_record(session_id, 5, 1).unwrap();
    let result = reg.check_and_record(session_id, 5, 2);
    assert!(result.is_ok());
    assert_eq!(reg.len(), 2);
}

#[test]
fn registry_survives_multiple_checks() {
    let mut reg = SmudgeSlotRegistry::new();
    let session_id = b"session-delta";

    for slot_id in 1..=10u16 {
        let result = reg.check_and_record(session_id, 1, slot_id);
        assert!(result.is_ok(), "slot_id={slot_id} should be accepted");
    }

    let err = reg.check_and_record(session_id, 1, 5).unwrap_err();
    assert!(matches!(
        err,
        PvssError::SmudgeSlotReused {
            party_id: 1,
            slot_id: 5,
        }
    ));
    assert_eq!(reg.len(), 10);
}
