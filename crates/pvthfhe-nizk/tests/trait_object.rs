//! Integration tests for `pvthfhe-nizk`: verifies `NizkAdapter` object-safety.
// RED test for plan task N1: NizkAdapter must be object-safe.
use pvthfhe_nizk::NizkAdapter;

#[test]
fn nizk_adapter_is_object_safe() {
    // Coercion to trait object will fail to compile if the trait is not object-safe.
    fn assert_object_safe(_: &dyn NizkAdapter) {}
    // We don't need a real impl here; the compile-time check is the assertion.
    let _ = assert_object_safe;
}
