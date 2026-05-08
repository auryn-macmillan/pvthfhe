//! RED-2: PVSS deal at n=256 must return an error whose Display names the cap (255).
//!
//! Currently FAILS because:
//!   (a) Display redacts the inner string (fixed by D1), AND
//!   (b) validate_context message does not mention "255" or "GF(256)" (fixed by D2a).
//! Will pass after both D1 and D2a are implemented.

use pvthfhe_pvss::{LatticePvssBfvAdapter, PvssAdapter, PvssContext};

fn make_adapter() -> LatticePvssBfvAdapter {
    LatticePvssBfvAdapter::new().expect("load adapter")
}

#[test]
fn deal_at_n_256_returns_error_naming_max() {
    let adapter = make_adapter();
    let ctx = PvssContext {
        n: 256,
        t: 129,
        session_id: vec![0u8; 16],
    };
    // 256 dummy public keys (content doesn't matter — validation fires before any crypto)
    let pks: Vec<Vec<u8>> = (0..256).map(|_| vec![0u8; 32]).collect();
    let err = adapter
        .deal(b"secret-seed-bytes", &pks, &ctx)
        .expect_err("deal must fail for n=256 (exceeds GF(256) cap)");
    let msg = format!("{err}");
    assert!(
        msg.contains("255") || msg.contains("GF(256)") || msg.contains("Shamir"),
        "error message must name the cap or the reason; got: {msg:?}"
    );
    assert!(
        msg.contains("256") || msg.contains("n=256"),
        "error message must mention the offending n; got: {msg:?}"
    );
}

#[test]
fn deal_at_n_255_does_not_fail_on_cap_check() {
    // n=255 is the maximum supported value; the cap check must NOT fire.
    // (The call may still fail for other reasons — e.g. malformed public keys —
    //  but the error must NOT be about n exceeding the cap.)
    let adapter = make_adapter();
    let ctx = PvssContext {
        n: 255,
        t: 128,
        session_id: vec![0u8; 16],
    };
    let pks: Vec<Vec<u8>> = (0..255).map(|_| vec![0u8; 32]).collect();
    match adapter.deal(b"secret-seed-bytes", &pks, &ctx) {
        Ok(_) => { /* fine */ }
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                !msg.contains("exceeds maximum") && !msg.contains("GF(256)"),
                "n=255 must not trigger the cap error; got: {msg:?}"
            );
        }
    }
}
