# Issues — p2-m4-lattice-commitment

## Pre-existing: compressor_verify failure (step 7)
- **Symptom**: `just demo-e2e` fails at "step 7/10: compressor_verify (nova-bn254-grumpkin)" with "nova compressed proof verification failed"
- **Confirmed**: Pre-existing — fails identically on unmodified `main` (git stash test)
- **Impact on this task**: None. Only step 5 (cyclo_fold) is affected by this change, and it passes.
- **Note**: This is a Nova Nova compressor issue, unrelated to the AjtaiMatrix wiring.
