//! Tests for the D2 hash-bridge commitment (hash_bridge.rs).

#[test]
fn d2_commit_golden_vector() {
    let sid = "test-session-2026";
    let pid = 7u16;
    let share = 0x0123_4567_89AB_CDEFu64;
    let c = pvthfhe_nizk::hash_bridge::commit(sid, pid, share);
    // hex from `python3 bench/scripts/hash_bridge_ref.py test-session-2026 7 81985529216486895`
    let expected_hex = "83e832e5d3c385393bd74cd74ba38857e89987b6b2a74a75e096b0a1e5ec597b";
    assert_eq!(hex::encode(c), expected_hex);
}

#[test]
fn d2_verify_roundtrip() {
    let sid = "roundtrip-session";
    let pid = 42u16;
    let share = 999_999_999_999u64;
    let c = pvthfhe_nizk::hash_bridge::commit(sid, pid, share);
    assert!(pvthfhe_nizk::hash_bridge::verify(&c, sid, pid, share));
    assert!(!pvthfhe_nizk::hash_bridge::verify(&c, sid, pid, share + 1));
}
