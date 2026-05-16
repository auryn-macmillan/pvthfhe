//! Build-time Stage-0 warning banner for `pvthfhe-fhe`.

fn main() {
    if std::env::var("CARGO_FEATURE_MOCK").is_ok() {
        println!(
            "cargo:warning=MOCK BACKEND ACTIVE — XOR/SHA256 ONLY. Set PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1 to use."
        );
    } else {
        println!(
            "cargo:warning=fhe: BFV backend is real (gnosisguild/fhe.rs); honest-but-curious threshold model."
        );
    }
}
