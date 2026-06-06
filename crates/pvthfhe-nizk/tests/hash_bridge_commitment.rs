//! Tests for H2 fix: consistent endianness + domain separator + length-prefixed
//! encoding in the D2 hash-bridge commitment.

use pvthfhe_nizk::hash_bridge;

#[test]
fn h2_roundtrip_commit_then_verify_passes() {
    let sid = "roundtrip-test-session";
    let pid = 42u16;
    let share = 999_999_999_999u64;
    let c = hash_bridge::commit(sid, pid, share);
    assert!(hash_bridge::verify(&c, sid, pid, share));
    assert!(!hash_bridge::verify(&c, sid, pid, share + 1));
}

#[test]
fn h2_endianness_injection_domain_separation() {
    // "abc" with participant_id=1 should NOT collide with "ab" with
    // participant_id=1 after the length prefix is included.
    // Without length-prefixed encoding, "abc"||1_le||s could collide with
    // "ab"||1_le||s if the third byte of session was misinterpreted.
    // With the fix (u32 length prefix in BE), these MUST differ.
    let c1 = hash_bridge::commit("abc", 1, 42);
    let c2 = hash_bridge::commit("ab", 1, 42);
    assert_ne!(
        c1, c2,
        "commit('abc',1,42) must not equal commit('ab',1,42)"
    );
}

#[test]
fn h2_different_participant_id_different_commitment() {
    let sid = "pid-test-session";
    let share = 42u64;
    let c1 = hash_bridge::commit(sid, 1, share);
    let c2 = hash_bridge::commit(sid, 2, share);
    assert_ne!(
        c1, c2,
        "different participant_id must produce different commitments"
    );
}

#[test]
fn h2_different_session_id_different_commitment() {
    let pid = 7u16;
    let share = 42u64;
    let c1 = hash_bridge::commit("session-alpha", pid, share);
    let c2 = hash_bridge::commit("session-beta", pid, share);
    assert_ne!(
        c1, c2,
        "different session_id must produce different commitments"
    );
}

#[test]
fn h2_golden_vector_fixed_encoding() {
    // Pre-computed golden vector with the FIXED encoding:
    // SHA256("pvthfhe-d2-hash-bridge/v1" || len(session_id) as u32 BE
    //        || session_id bytes || participant_id as u16 BE || secret_share as u64 BE)
    //
    // session_id = "test-session-2026" (len=17 = 0x00000011)
    // participant_id = 7u16 (0x0007 BE)
    // secret_share = 0x0123_4567_89AB_CDEFu64
    let sid = "test-session-2026";
    let pid = 7u16;
    let share = 0x0123_4567_89AB_CDEFu64;
    let c = hash_bridge::commit(sid, pid, share);
    // SHA256("pvthfhe-d2-hash-bridge/v1" +
    //        b'\x00\x00\x00\x11' + b"test-session-2026" +
    //        b'\x00\x07' + b'\x01\x23\x45\x67\x89\xab\xcd\xef')
    let expected_hex = "9b0e869cd204bc5bd086c57fb866d1c8ced8281a0fe4ce28e1331a39afae7a66";
    assert_eq!(hex::encode(c), expected_hex);
}
