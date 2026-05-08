//! RED-1: PvssError::BackendError Display must surface the inner string.
//!
//! Currently FAILS because Display prints only "PVSS backend error" (redacted).
//! Will pass after D1 implementation changes lib.rs:104.

use pvthfhe_pvss::PvssError;

#[test]
fn backend_error_display_includes_inner_string() {
    let e = PvssError::BackendError("invalid PVSS context: n=256, t=129".into());
    let s = format!("{e}");
    assert!(
        s.contains("invalid PVSS context"),
        "Display must include inner string; got: {s:?}"
    );
    assert!(
        s.contains("256"),
        "Display must include n=256 from inner string; got: {s:?}"
    );
}

#[test]
fn backend_error_display_generic_message_still_present() {
    let e = PvssError::BackendError("some backend failure".into());
    let s = format!("{e}");
    // The display should still contain a recognisable prefix so callers can
    // pattern-match on "PVSS backend error" if they want.
    assert!(
        s.contains("PVSS") || s.contains("backend") || s.contains("some backend failure"),
        "Display must be non-empty and meaningful; got: {s:?}"
    );
}
