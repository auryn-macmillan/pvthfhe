# Learnings — pvthfhe-skeptical-audit

## 2026-05-03 Session Start — Ground Truth Scan

### Confirmed Facts
- **P3RealVerifier.sol**: Line ~64 is `ecrecover` against hardcoded `TRUSTED_SIGNER = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`. Confirmed vacuous.
- **SURROGATE markers**: Present in 5 files. `fhers.rs` has MANY inline markers (lines 27,33,38,48,58,68). `protocol.rs` line 1 is a SURROGATE header. `circuits/aggregator_final/src/main.nr` line 5,7. `circuits/decrypt_share/src/main.nr` lines 2,47.
- **hermine.rs**: Line 1 is `#![allow(clippy::as_conversions, clippy::manual_contains)]` — confirmed.
- **obligations.md**: `grep -c "^|"` = 22 (2 header rows + 20 data rows = 20 theorems confirmed).
- **paper/main.tex**: `grep -c '\\begin{theorem}'` = 19 (1 theorem is missing from paper vs 20 obligations — discrepancy confirmed).
- **P3RealVerifier.sol key lines**: TRUSTED_SIGNER on lines 31-32, ecrecover on lines ~62-65.

### Key File Paths
- Verifier: `contracts/src/P3RealVerifier.sol` (ecrecover on ~line 64)
- NIZK: `crates/pvthfhe-fhe/src/fhers.rs` (stub, many SURROGATE markers)
- Aggregator keygen shim: `crates/pvthfhe-aggregator/src/keygen/protocol.rs` (4 lines, SURROGATE line 1)
- Clippy suppression: `crates/pvthfhe-keygen/src/hermine.rs` (line 1 allow directive)
- Noir circuits: `circuits/aggregator_final/src/main.nr`, `circuits/decrypt_share/src/main.nr`
- HonkVerifier surrogate: `contracts/src/generated/HonkVerifier.sol` (line 4 marker)

### Toolchain conventions (from AGENTS.md)
- Foundry: `forge ... --root contracts` from repo root
- Noir: `(cd circuits && nargo ...)` from repo root
- Cargo: from repo root with `-p <crate>`
- TDD: RED test before every implementation change
- Stub protocol: replace in place, NEVER delete-and-recreate

### Canonical Noir+BB flow
1. `nargo execute --package <pkg> --prover-name <Prover_name>`
2. `bb write_vk --scheme ultra_honk -b target/<pkg>.json -o target`
3. `bb prove --scheme ultra_honk -b target/<pkg>.json -w target/<pkg>.gz -o target`
4. `bb verify --scheme ultra_honk -k target/vk -p target/proof -i target/public_inputs`
FORBIDDEN: `nargo prove`, `nargo verify`

## P3RealVerifier Vacuity (T1)

- `P3RealVerifier` is Option C (ECDSA surrogate) — only checks trusted-signer ECDSA sig
- ecrecover call site: `P3RealVerifier.sol:63`
- TRUSTED_SIGNER hardcoded at line 30-31 = Anvil #0 = `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`
- Vacuity test pattern: craft false 200-byte publicInputs, sign with `vm.sign(TRUSTED_SIGNER_PK, digest)`, assert `verify()` returns true
- Test `testVacuousVerifierAcceptsFalseClaim` PASSES — confirming verifier cannot reject false FHE claims
- Unicode chars in string literals cause Solc 0.8.x compile error — use ASCII only
