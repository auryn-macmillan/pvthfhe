

## 2026-05-02 — Oracle review findings
- Critical inconsistency across Phase 2 docs: decryption/key algebra alternates between plain share summation, Lagrange-weighted reconstruction, and subset-specific aggregate keys.
- Decryption-share proof statement is not bound to DKG public-key material or participant identity, leaving a rogue-share / rogue-key gap.
- On-chain verifier ABI is infeasible against the 5M gas target: calldata lower bound alone exceeds the ceiling before proof verification.


## 2026-05-02 — Oracle re-review round 2
- Still-open criticals: F-001 algebra consistency, F-002 share/DKG binding, F-003 frozen verifier statement, F-005 public DKG transcript/verifier completeness.
- Still-open highs: F-006 unsupported 128-bit claim wording, F-007 incorrect authentication language, F-008 incomplete replay/session binding, F-010 muddled IND-CPA model/hybrids, F-011 over-strong smudging privacy claim.
- Still-open mediums: F-013 undefined `ComplaintProof` comparison target, F-015 unsupported concrete Architecture-B gas/proof-size claims.
## 2026-05-02

- `cargo clippy --workspace --all-targets -- -D clippy::unwrap_used` reports many pre-existing warnings unrelated to unwrap/expect (missing docs, panic, as-conversions). The unwrap lint in the targeted test files is now suppressed, but the workspace command still does not exit cleanly because of those other warnings.
