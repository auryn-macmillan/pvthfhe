//! Tests for the D2 hash-bridge commitment (hash_bridge.rs).
//! H2 fix: updated golden vector for consistent BE + domain + length-prefixed encoding.

#[test]
fn d2_commit_golden_vector() {
    let sid = "test-session-2026";
    let pid = 7u16;
    let share = 0x0123_4567_89AB_CDEFu64;
    let c = pvthfhe_nizk::hash_bridge::commit(sid, pid, share);
    // SHA256("pvthfhe-d2-hash-bridge/v1" || len(sid)=17u32 BE || sid || pid BE || share BE)
    let expected_hex = "9b0e869cd204bc5bd086c57fb866d1c8ced8281a0fe4ce28e1331a39afae7a66";
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
