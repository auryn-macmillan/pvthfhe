# Learnings: Remove d_commitment from aggregator_final circuit

## Pattern: Non-ASCII character in comment breaks Noir compilation
- `→` (right arrow) is not valid in Noir comments
- Replace with `->` for ASCII compatibility

## Pattern: Removing params from Noir main function
- Removing a param from `fn main()` requires updating ALL test call sites
- When multiple tests share similar code patterns for the removed param, use
  unique surrounding context (e.g., function name + adjacent function name) to
  disambiguate Edit calls

## Test count change
- `test_tamper_d_commitment_mismatch` was removed entirely since d_commitment
  is now verified on-chain (HonkVerifier.sol), not in-circuit
- 9 original tests → 8 remaining tests (all pass)
