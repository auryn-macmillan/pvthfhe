# SURROGATE Reachability Matrix

Generated: 2026-05-03  
Method: grep reference tracing + `cargo build` / `cargo build --tests` / `cargo build --release`

---

## 5×3 Table

| File | Default | Test | Release | Verdict |
|------|---------|------|---------|---------|
| `contracts/src/generated/HonkVerifier.sol` | **LIVE** | **LIVE** | **LIVE** | LIVE |
| `circuits/aggregator_final/src/main.nr` | **DEAD** (Noir only) | **TEST-ONLY** (nargo test) | **DEAD** | DEAD (Rust builds); TEST-ONLY (Noir) |
| `circuits/decrypt_share/src/main.nr` | **DEAD** (Noir only) | **TEST-ONLY** (nargo test) | **DEAD** | DEAD (Rust builds); TEST-ONLY (Noir) |
| `crates/pvthfhe-fhe/src/fhers.rs` | **LIVE** | **LIVE** | **LIVE** | LIVE |
| `crates/pvthfhe-aggregator/src/keygen/protocol.rs` | **LIVE** (compiled, no-op symbols) | **LIVE** | **LIVE** | LIVE (compiled; zero exported symbols) |

---

## Per-File Evidence

### 1. `contracts/src/generated/HonkVerifier.sol`

| Profile | Status | Evidence |
|---------|--------|----------|
| Default | LIVE | `contracts/src/PvtFheVerifier.sol:4` — `import "./generated/HonkVerifier.sol"` + `PvtFheVerifier.sol:77` — `_honkVerifier = new HonkVerifier()` |
| Test | LIVE | `contracts/test/PvtFheVerifier.e2e.t.sol:5` — `import "../src/generated/HonkVerifier.sol"` + instantiated at line 15 |
| Release | LIVE | Same production contract path; no separate release exclusion |

**Verdict: LIVE** — imported by the production `PvtFheVerifier.sol` in all build profiles. The surrogate keccak-equality check is active in all deployments until P2 is resolved.

---

### 2. `circuits/aggregator_final/src/main.nr`

| Profile | Status | Evidence |
|---------|--------|----------|
| Default (cargo) | DEAD | `pvthfhe-circuits/src/lib.rs` — placeholder only; no Rust code references this circuit. `grep -rn "aggregator_final"` finds no Rust import. |
| Test (cargo `--tests`) | DEAD | Same; no Rust integration test invokes this circuit. |
| Release (cargo) | DEAD | Same. |
| Noir workspace | TEST-ONLY | `circuits/Nargo.toml:5` — workspace member `"aggregator_final"`; `nargo test` would run it. No `Prover.toml`/`nargo execute` flow wires it at CI-default. |

**Verdict: DEAD** under Rust build profiles. TEST-ONLY under Noir (`nargo test`). Not executed or proven in any automated CI path (no `nargo execute` call found).

---

### 3. `circuits/decrypt_share/src/main.nr`

| Profile | Status | Evidence |
|---------|--------|----------|
| Default (cargo) | DEAD | No Rust crate imports this Noir package. `pvthfhe-circuits` is a placeholder. `grep` finds `surrogate-decrypt-share` Cargo feature in `pvthfhe-fhe/Cargo.toml:11` but this feature gates Rust NIZK behaviour, not the Noir circuit. |
| Test (cargo `--tests`) | DEAD | Conformance/NIZK tests in `pvthfhe-fhe/tests/` test the Rust NIZK shim, not the Noir circuit. |
| Release (cargo) | DEAD | Same. |
| Noir workspace | TEST-ONLY | `circuits/Nargo.toml:4` — workspace member `"decrypt_share"`; contains 7 `#[test]` functions in `main.nr` (`test_honest`, `test_fail_*`). `nargo test` exercises these. |

**Verdict: DEAD** under Rust build profiles. TEST-ONLY under Noir (`nargo test`). The Rust `surrogate-decrypt-share` feature is an independent placeholder flag that does not invoke the Noir circuit.

---

### 4. `crates/pvthfhe-fhe/src/fhers.rs`

| Profile | Status | Evidence |
|---------|--------|----------|
| Default | LIVE | `crates/pvthfhe-fhe/src/lib.rs:12` — `pub mod fhers;`; compiled as part of the public API of the `pvthfhe-fhe` crate, which is a workspace member. `cargo build` compiles `pvthfhe-fhe`. |
| Test | LIVE | `crates/pvthfhe-fhe/tests/conformance.rs:143` — `use pvthfhe_fhe::fhers::FhersBackend;`; 4 conformance tests (`primary_load_params`, `primary_keygen_share`, `primary_encrypt`, `primary_decrypt_share_party_id`) instantiate `FhersBackend` at lines 147, 152, 158, 164. |
| Release | LIVE | `pvthfhe-fhe` compiled in release; all methods delegate to `MockBackendInner`. |

**Verdict: LIVE** — the struct is instantiated and exercised by conformance tests. All method bodies execute (via mock delegation) in all three profiles.

---

### 5. `crates/pvthfhe-aggregator/src/keygen/protocol.rs`

| Profile | Status | Evidence |
|---------|--------|----------|
| Default | LIVE (compiled, zero symbols) | `crates/pvthfhe-aggregator/src/keygen/mod.rs:3` — `pub mod protocol;`; compiled as part of `pvthfhe-aggregator`. The file contains 4 lines of comments and no Rust items. |
| Test | LIVE (compiled, zero symbols) | Same; `pvthfhe-aggregator` compiled with `--tests`. External tests use `keygen::simulator`, not `keygen::protocol`. |
| Release | LIVE (compiled, zero symbols) | Same. |

**Verdict: LIVE** (compiled) but functionally **DEAD** — the module emits no items, exports nothing, and is never directly imported by any external crate or test. It is a pure comment placeholder that happens to be included in the module tree via `pub mod protocol`.

---

## Build Log Summary

All three profiles succeeded with exit code 0:

- `cargo build` — `Finished dev profile` in 9.38s
- `cargo build --tests` — `Finished dev profile` in 12.91s  
- `cargo build --release` — `Finished release profile` in 18.53s

Full logs: `.sisyphus/evidence/audit-surrogate/cargo-build.log`

---

## Reference Logs

- `audit-surrogate/grep-HonkVerifier.log` — Solidity import chain
- `audit-surrogate/grep-aggregator_final.log` — Noir workspace + evidence JSON refs
- `audit-surrogate/grep-decrypt_share.log` — Noir workspace + Rust NIZK shim refs
- `audit-surrogate/grep-fhers.log` — FhersBackend test imports
- `audit-surrogate/grep-protocol.log` — keygen::protocol module exports
- `audit-surrogate/cargo-build.log` — full build output for all three profiles
