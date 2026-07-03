# Security Audit Remediation Plan

**Date:** 2026-07-02  
**Audit Scope:** pvthfhe cryptographic completeness, robustness, and fault tolerance  
**Status:** Draft - Awaiting Momus review

## Executive Summary

This remediation plan addresses the security findings from the comprehensive audit conducted on 2026-07-02. The plan prioritizes high-impact vulnerabilities that undermine the system's cryptographic soundness and fault tolerance.

**Key Statistics:**
- **Critical Findings:** 3 (P1, P2, F6)
- **High Priority Findings:** 4 (F5, F7, F8, F9)
- **Medium/Low Findings:** 6 (F10, F11, F12, F13, P4, and others)
- **Estimated Effort:** 80-120 hours
- **Timeline:** 2-3 weeks for full remediation

## Priority 0: Immediate Actions (This Week)

### P0-1: Eliminate Dangerous .expect() Calls

**Finding:** F6 - `.expect()` in NIZK paths destroy blame context  
**Severity:** HIGH  
**Status:** REMAINING

**Action Items:**
1. **Replace all `.expect()` in cryptographic paths** with proper error propagation
2. **Add party_id to all error variants** for blame attribution
3. **Implement error context tracking** to preserve failure information

**Files to Modify:**
- `crates/pvthfhe-nizk/src/adapter.rs`
- `crates/pvthfhe-nizk/src/sigma.rs`
- `crates/pvthfhe-pvss/src/nizk_share.rs`
- `crates/pvthfhe-pvss/src/nizk_decrypt.rs`

**Success Criteria:**
- All cryptographic operations return `Result<T, E>` with meaningful errors
- No `.expect()` calls in production code paths that can be triggered by adversarial input
- Error messages include party identifiers where applicable

### P0-2: Add Party Context to All Errors

**Finding:** F5 - NIZK errors are opaque (no party ID)  
**Severity:** MEDIUM (but enables other fixes)  
**Status:** REMAINING

**Action Items:**
1. **Update error enums** to include `party_id: Option<u16>` in all variants
2. **Propagate party_id** through all function calls
3. **Update error handling** in callers to preserve party context

**Files to Modify:**
- `crates/pvthfhe-nizk/src/lib.rs` - `NizkError` enum
- `crates/pvthfhe-pvss/src/lib.rs` - `PvssError` enum
- `crates/pvthfhe-keygen/src/dkg.rs` - `DkgError` enum

**Success Criteria:**
- All error variants that relate to party-specific operations include `party_id`
- Error messages clearly identify which party caused the failure
- Blame attribution works correctly in abort scenarios

## Priority 1: High Impact (This Month)

### P1-1: Resolve Lattice NIZK Soundness (Open Problem P1)

**Finding:** P1 - Lattice NIZK well-formedness soundness  
**Severity:** CRITICAL  
**Status:** OPEN PROBLEM

**Action Items:**
1. **Formalize extractor construction** for the lattice NIZK
2. **Prove knowledge soundness** under Module-SIS assumption
3. **Document as explicit assumption** if proof cannot be completed

**Required Expertise:** Cryptographic theory, lattice-based cryptography

**Success Criteria:**
- Either a formal proof of knowledge soundness, OR
- Explicit documentation of the assumption with security analysis

### P1-2: Resolve LatticeFold+ Soundness (Open Problem P2)

**Finding:** P2 - LatticeFold+ over RLWE folding argument  
**Severity:** HIGH  
**Status:** OPEN PROBLEM

**Action Items:**
1. **Prove Lemma 9** (invertibility of folding matrix)
2. **Verify folding relation** is binding and hiding
3. **Document as explicit assumption** if proof cannot be completed

**Required Expertise:** Lattice cryptography, folding schemes

**Success Criteria:**
- Either a formal proof of folding soundness, OR
- Explicit documentation of the assumption with security analysis

### P1-3: Implement MPC Round Timeouts

**Finding:** F7 - No MPC round timeouts  
**Severity:** MEDIUM  
**Status:** REMAINING

**Action Items:**
1. **Add timeout parameters** to DKG session and decryption aggregation
2. **Implement timeout detection** with configurable Δ₁, Δ₂
3. **Add abort logic** that issues `BlameProof` on timeout
4. **Implement state cleanup** on timeout

**Files to Modify:**
- `crates/pvthfhe-keygen/src/dkg.rs`
- `crates/pvthfhe-aggregator/src/decrypt.rs`
- `crates/pvthfhe-types/src/lib.rs` - Add timeout types

**Success Criteria:**
- All DKG rounds have timeout mechanisms
- Timeouts trigger proper blame attribution
- No indefinite stalling possible under adversarial conditions

### P1-4: Fix F9 - Secure Deserialization of G1Affine

**Finding:** F9 - `NonEquivSignature::from_bytes` uses `new_unchecked`  
**Severity:** LOW  
**Status:** REMAINING

**Action Items:**
1. **Validate curve membership** during deserialization
2. **Return error** for off-curve points
3. **Add tests** for off-curve rejection

**Files to Modify:**
- `crates/pvthfhe-non-equiv/src/lib.rs` - `NonEquivSignature::from_bytes`

**Success Criteria:**
- `from_bytes` validates points are on BN254 curve
- Off-curve points are rejected with appropriate error
- Tests verify rejection of invalid points

## Priority 2: Medium Impact (Next Quarter)

### P2-1: Implement Explicit Abort API

**Finding:** F11 - No abort-time explicit state reset API  
**Severity:** LOW  
**Status:** REMAINING

**Action Items:**
1. **Add `fn abort()` or `fn reset()`** to protocol state structs
2. **Implement zeroization** of sensitive data on abort
3. **Ensure Drop implementations** are robust

**Files to Modify:**
- `crates/pvthfhe-fhe/src/fhers.rs`
- `crates/pvthfhe-pvss/src/lib.rs`
- `crates/pvthfhe-aggregator/src/lib.rs`

**Success Criteria:**
- Explicit abort API available for all protocol state
- Sensitive data is zeroized on abort
- No sensitive data remains in memory after abort

### P2-2: Improve DkgError Party Context

**Finding:** F8 - Opaque DkgError loses party context  
**Severity:** LOW  
**Status:** REMAINING

**Action Items:**
1. **Update DkgError variants** to include party_id
2. **Propagate party_id** through DKG operations
3. **Improve error messages** with party identifiers

**Files to Modify:**
- `crates/pvthfhe-keygen/src/dkg.rs` - `DkgError` enum

**Success Criteria:**
- All DkgError variants include party context where applicable
- Error messages clearly identify the responsible party
- Blame attribution works for DKG failures

## Priority 3: Low Impact (Future Work)

### P3-1: Add Cross-Instance Abort Propagation

**Finding:** F12 - No cross-instance abort propagation  
**Severity:** INFO  
**Status:** NOT APPLICABLE

**Note:** This is for multi-party deployment scenarios. Currently not applicable to single-process sequential execution.

### P3-2: Validate FHE Wire Type Coefficients

**Finding:** F13 - FHE wire types don't validate algebraic coefficient domains  
**Severity:** INFO  
**Status:** ACCEPTED AS IS

**Note:** Marked as research prototype limitation. Wire types accept coefficient bytes without full validation.

### P3-3: Fix F10 - Decode Functions Return Errors

**Finding:** F10 - `decode_i64_vec` silent return on truncation  
**Severity:** LOW  
**Status:** REMAINING

**Action Items:**
1. **Update `decode_i64_vec`** to return `Result` instead of empty vector
2. **Propagate error** to callers
3. **Add tests** for truncated input handling

**Files to Modify:**
- `crates/pvthfhe-pvss/src/nizk_keygen.rs` - `decode_i64_vec`

**Success Criteria:**
- `decode_i64_vec` returns `Err` on truncated input
- Callers handle the error appropriately
- Tests verify error on truncation

## Implementation Order

The following order ensures dependencies are resolved and testing is maximized:

1. **P0-2** (Error context) - Foundation for other fixes
2. **P0-1** (Remove .expect()) - Improves robustness
3. **P1-3** (Timeouts) - Requires error handling
4. **P1-4** (Deserialization) - Independent fix
5. **P1-1** (P1 soundness) - Theoretical work, can run in parallel
6. **P1-2** (P2 soundness) - Theoretical work, can run in parallel
7. **P2-1** (Abort API) - Requires error handling
8. **P2-2** (DkgError) - Requires error handling
9. **P3-3** (Decode errors) - Requires error handling

## Verification Strategy

### RED Tests
- All findings have corresponding RED tests in `crates/pvthfhe-tests/tests/security_audit_reds.rs`
- RED tests should FAIL before the fix and PASS after
- Tests must be integrated into CI pipeline

### Manual Verification
1. **Code Review:** All changes reviewed by cryptographic experts
2. **Formal Methods:** Consider formal verification for critical components
3. **Adversarial Testing:** Run full adversarial test suite
4. **Performance Testing:** Verify no regressions in throughput

### CI Pipeline Updates
- Add security audit RED tests to CI
- Require all RED tests to pass before merge
- Add static analysis for `.expect()` usage

## Rollback Plan

If any remediation causes issues:
1. **Revert the specific change** using git
2. **Run full test suite** to ensure no regressions
3. **Assess alternative approach** if needed
4. **Document rollback** and rationale

## Success Metrics

- **0** critical vulnerabilities open
- **100%** of error variants include party context
- **0** `.expect()` calls in production cryptographic paths
- **All** RED tests pass consistently
- **Formal proofs** or explicit assumptions for P1 and P2

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| P1/P2 proofs cannot be completed | High | Document as assumptions, add fallback mechanisms |
| Error handling changes break existing code | Medium | Comprehensive testing, gradual rollout |
| Performance regressions from timeouts | Low | Tune timeout parameters, adaptive timeouts |
| Deserialization validation slows signing | Low | Batch validation, optional validation |

## Conclusion

This remediation plan addresses the most critical security gaps identified in the audit. By following this plan, PVTHFHE can achieve a much stronger security posture and move closer to production readiness.

**Next Steps:**
1. Submit this plan to Momus for review
2. Assign owners to each action item
3. Begin implementation with P0-2 and P0-1
4. Establish regular security review cadence

---

*This plan will be updated as work progresses and new findings emerge.*
