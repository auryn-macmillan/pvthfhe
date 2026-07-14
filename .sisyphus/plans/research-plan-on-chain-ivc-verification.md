# Security Research Plan: On-Chain IVC Verification via UltraHonk Proofs

**Date**: 2026-07-03  
**Status**: Draft - Awaiting Momus review  
**Author**: Security Audit Team  
**Related**: SECURITY.md, OPEN-PROBLEM-BLOCKERS.md (P4)

## Executive Summary

This plan addresses the P4 open problem (On-chain IVC decider verification) by transforming the current hybrid verification approach into a fully on-chain verified system. The goal is to generate UltraHonk proofs that attest to the correctness of IVC verification, allowing on-chain verification without trusting the off-chain verifier.

**Current State**: IVC verification happens off-chain in Rust, circuit checks `ivc_verify_result == 1`, trust needed in off-chain verifier.

**Target State**: Generate UltraHonk proof of verification correctness, verify on-chain in Solidity contract, eliminate trust assumptions.

## Problem Statement

### Current Architecture
1. **Off-chain**: Full IVC verification in Rust using `LatticeFoldVerifier.verify()`
2. **Result**: `ivc_verify_result` boolean (1 = success, 0 = failure)
3. **On-chain**: Noir circuit checks `assert(ivc_verify_result == 1)`
4. **Trust assumption**: Need to trust that `ivc_verify_result` was computed correctly by off-chain verifier

### Security Gap
The current approach requires trusting that the off-chain verifier computed the result correctly. This violates the principle of **minimal trust assumptions** and creates a potential attack surface if the off-chain verification is compromised.

## Research Objectives

### Objective 1: Verification Logic Analysis
- **Question**: What are the exact inputs, state transformations, and outputs of `LatticeFoldVerifier.verify()`?
- **File**: `crates/pvthfhe-compressor/src/latticefold/verifier.rs`
- **Output**: Detailed specification of verification preconditions, postconditions, and what exactly is proven

### Objective 2: Proof Generation Strategy
- **Question**: How can we generate an UltraHonk proof that the verification logic was executed correctly on given inputs?
- **File**: `crates/pvthfhe-compressor/src/latticefold/compressor.rs`
- **Output**: Proof generation workflow, required inputs, expected outputs

### Objective 3: Noir Circuit Integration
- **Question**: How to modify `nova_state_commitment` circuit to verify UltraHonk proof instead of checking `ivc_verify_result`?
- **File**: `circuits/nova_state_commitment/src/main.nr`
- **Output**: Circuit modification plan, expected circuit size changes

### Objective 4: Solidity Verifier Contract
- **Question**: How to create a contract that verifies UltraHonk proofs?
- **File**: `contracts/src/`
- **Output**: Contract interface, gas costs, deployment requirements

### Objective 5: Pipeline Integration
- **Question**: How does this fit into the existing `just demo-e2e` flow?
- **Output**: Modified pipeline steps, timing implications

### Objective 6: Security Analysis
- **Question**: Does this maintain the same security guarantees as current approach?
- **Output**: Trust assumption changes, potential new attack vectors

## Expected Deliverables

1. **Detailed specification** of what needs to be proven
2. **Proof generation workflow** with code examples
3. **Circuit modification plan** with before/after comparisons
4. **Solidity verifier contract** draft
5. **Gas and circuit size estimates**
6. **Security analysis** comparing approaches

## Timeline

### Week 1: Verification Logic Analysis
- Analyze `LatticeFoldVerifier.verify()` implementation
- Document verification preconditions/postconditions
- Identify what needs to be proven

### Week 2: Proof Generation Design
- Design UltraHonk proof generation workflow
- Define proof data structures
- Estimate proof generation complexity

### Week 3: Circuit and Contract Design
- Modify Noir circuit for proof verification
- Draft Solidity verifier contract
- Estimate circuit size and gas costs

### Week 4: Pipeline Integration
- Integrate proof generation into demo-e2e flow
- Update CLI commands
- Write integration tests

### Week 5: Security Analysis and Optimization
- Perform security analysis
- Optimize circuit size and gas costs
- Document findings and recommendations

## Success Criteria

1. **Research provides sufficient context** to write a concrete implementation plan
2. **All technical challenges** are identified and documented
3. **Security guarantees** are clearly defined and maintained
4. **Gas and circuit size estimates** are realistic and within targets

### Quantitative Metrics
- **Circuit size**: < 10,000 ACIR opcodes
- **Proof size**: < 50 KB
- **Verification gas**: < 300,000 gas
- **Security**: Maintain equivalent or better security than current approach

## Risk Assessment

### High Risks
1. **Proof generation too slow**
   - **Impact**: Demo-e2e flow becomes impractical
   - **Mitigation**: Optimize verification logic, parallelize generation

2. **Circuit size too large**
   - **Impact**: Circuit exceeds Noir compiler limits
   - **Mitigation**: Use Schwartz-Zippel evaluation, optimize constraints

3. **Gas costs too high**
   - **Impact**: On-chain verification becomes prohibitively expensive
   - **Mitigation**: Batch verifications, optimize proof format

### Medium Risks
1. **Proof system compatibility**
   - **Impact**: UltraHonk proof generation fails
   - **Mitigation**: Use alternative proof system (e.g., Plonk)

2. **Noir compiler limitations**
   - **Impact**: Cannot implement verification in Noir
   - **Mitigation**: Use recursive proof approach

### Low Risks
1. **Security assumptions change**
   - **Impact**: New attack vectors emerge
   - **Mitigation**: Formal verification, security audit

## Dependencies

### Technical Dependencies
- **Noir 1.0.0-beta.22+**: Required for UltraHonk proof verification
- **Barretenberg 5.0.0-nightly.20260522+**: Required for proof generation
- **Foundry**: Required for Solidity contract testing

### Code Dependencies
- `crates/pvthfhe-compressor/src/latticefold/verifier.rs`
- `crates/pvthfhe-compressor/src/latticefold/compressor.rs`
- `circuits/nova_state_commitment/src/main.nr`
- `contracts/src/`

## Approval Required

This research plan requires approval from Momus before implementation begins. The plan will be evaluated on:

1. **Feasibility**: Can the research be completed within the timeline?
2. **Completeness**: Are all critical areas addressed?
3. **Risk awareness**: Are risks properly identified and mitigated?
4. **Success criteria**: Are metrics measurable and realistic?

## Next Steps

1. **Momus review** - Evaluate plan and provide feedback
2. **Research phase** - Complete all research objectives
3. **Implementation plan** - Write detailed implementation based on research
4. **Implementation phase** - Execute implementation plan
5. **Validation** - Test and validate final implementation

---

*This plan will be updated as research progresses and new findings emerge.*
