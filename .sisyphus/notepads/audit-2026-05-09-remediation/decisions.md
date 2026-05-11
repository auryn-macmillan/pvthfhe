# Decisions — Batch A.3: Fix Fiat-Shamir challenge binding (C13)

## Decision: Don't add verifier-side commitment_seed verification

The verifier trusts `opened.commitment_seed` without verifying it equals `compute_commitment_seed(stmt)`. 
This is acceptable because:
1. `lattice_binding` includes `commitment_seed` in its hash — any tampering changes it
2. `verify_d2_hash_binding` recovers the share from commitment_ct using commitment_seed — 
   a wrong seed produces garbage that fails the D2 binding check
3. The verifier doesn't need to independently verify the seed as long as the lattice 
   binding correctly binds it to the rest of the proof

## Decision: Bump commitment_seed domain tag to v2

The `compute_commitment_seed` function changed from `hash(stmt + challenge)` to `hash(stmt only)`, 
so the domain tag was bumped from `greco-bfv-commitment-seed-v1` to `greco-bfv-commitment-seed-v2` 
to prevent ambiguity in serialized proofs.
