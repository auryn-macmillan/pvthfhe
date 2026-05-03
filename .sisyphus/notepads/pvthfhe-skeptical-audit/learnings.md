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

## T2: SURROGATE Reachability (2026-05-03)

- **HonkVerifier.sol** is LIVE in all profiles: imported both by the production `PvtFheVerifier.sol` (default/release) and the e2e test (`PvtFheVerifier.e2e.t.sol`). Surrogate keccak check is active everywhere.
- **aggregator_final/src/main.nr** and **decrypt_share/src/main.nr** are DEAD under all Rust build profiles. `pvthfhe-circuits` crate is a placeholder with only a trivial `#[test] fn placeholder()`. The circuits are only reachable via `nargo test` (Noir-only). They are Noir workspace members but not invoked by any Rust integration test.
- **fhers.rs** is LIVE: `pub mod fhers` in lib.rs + 4 conformance tests directly instantiate `FhersBackend`. All methods delegate to MockBackendInner (surrogate delegation pattern).
- **keygen/protocol.rs** is compiled (LIVE in the sense of being in the module tree via `pub mod protocol`) but has zero Rust items — only 4 comment lines. No external crate or test references `keygen::protocol` directly. Functionally DEAD.
- `*.log` files are gitignored globally; must use `git add -f` for evidence logs in `.sisyphus/evidence/`.

## T3 Cast Audit — hermine.rs (2026-05-03)

- `grep -nE ' as [a-z_][a-z0-9_]*'` returns 18 lines but 2 are doc-comment false-positives ("used as the Shamir", "byte slice as a lowercase"). Actual code casts = 16 across 14 source lines (two lines hold 2 casts each).
- All u64→u128 widening casts in `poly_eval` and `lagrange_interpolate` are safe; arithmetic is always reduced `% PRIME` before narrowing back to u64, so the one u128→u64 narrow cast at lines 46 and 208 is also safe.
- **Single truncating cast**: line 367 `threshold as u16` (usize→u16). The `threshold` local is derived via `as usize` from a `u16` value, so in practice the value can never exceed u16::MAX in current code — but it is still an unsound pattern. Fix for T19: `u16::try_from(threshold)?`.
- **One `manual_contains`**: line 413 — `iter().any(|c| *c == expected_commit)` → `commitments.contains(&expected_commit)`.
