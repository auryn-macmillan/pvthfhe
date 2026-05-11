# Issues: fhe.rs threshold guard

## Pre-existing: PVSS D2 hash binding failure

Even with valid (n,t) parameters that satisfy `t <= (n-1)/2`, the pipeline fails at the PVSS step
with "pvss verify_shares: PVSS D2 hash binding verification failed". This is a pre-existing issue
unrelated to the threshold guard. 

Combinations tested:
- n=5, t=2 (max_t=2) → PVSS D2 hash binding failure
- n=3, t=1 (max_t=1) → not yet tested

This issue predates the threshold guard work and needs separate investigation.
