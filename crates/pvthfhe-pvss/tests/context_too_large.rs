//! R1.2 GREEN: PVSS deal party-count cap test (BN254 field removes GF(256) cap).
//!
//! The BN254 scalar field supports far more parties than GF(256) did.
//! We keep a sanity cap of 65535 parties (configurable in `encrypt.rs`) to
//! guard against accidentally huge `n` values.

use pvthfhe_pvss::{LatticePvssBfvAdapter, PvssAdapter, PvssContext};

fn make_adapter() -> LatticePvssBfvAdapter {
    LatticePvssBfvAdapter::new().expect("load adapter")
}

#[test]
fn deal_at_n_65536_returns_error_naming_max() {
    let adapter = make_adapter();
    let ctx = PvssContext {
        n: 65536,
        t: 32768,
        session_id: vec![0u8; 16],
        epoch: 0,
        dkg_root: vec![],
    };
    // validate_context fires before the recipient_pks length check,
    // so we do not need to allocate 65536 dummy public keys.
    let pks: Vec<Vec<u8>> = Vec::new();
    let err = adapter
        .deal(b"secret-seed-bytes", &pks, &ctx)
        .expect_err("deal must fail for n=65536 (exceeds sanity cap)");
    let msg = format!("{err}");
    assert!(
        msg.contains("65535") || msg.contains("maximum supported parties"),
        "error message must name the cap or the reason; got: {msg:?}"
    );
    assert!(
        msg.contains("65536") || msg.contains("n=65536"),
        "error message must mention the offending n; got: {msg:?}"
    );
}

#[test]
fn deal_at_n_65535_does_not_fail_on_cap_check() {
    // n=65535 is the maximum allowed; the cap check must NOT fire.
    // The call may fail for other reasons (e.g. malformed public keys)
    // but the error must NOT be about n exceeding the cap.
    let adapter = make_adapter();
    let ctx = PvssContext {
        n: 65535,
        t: 32768,
        session_id: vec![0u8; 16],
        epoch: 0,
        dkg_root: vec![],
    };
    // We only need to prove the cap does not reject n=65535;
    // a key-count mismatch error is acceptable.
    let pks: Vec<Vec<u8>> = Vec::new();
    match adapter.deal(b"secret-seed-bytes", &pks, &ctx) {
        Ok(_) => { /* fine */ }
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                !msg.contains("exceeds maximum") && !msg.contains("65535"),
                "n=65535 must not trigger the cap error; got: {msg:?}"
            );
        }
    }
}
