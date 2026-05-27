# P3-M1 Decisions

## state_len=3 instead of 2
- **Decision**: Changed FoldVerifierStepCircuit from 2-element to 3-element state.
- **Rationale**: NovaCompressor internally pushes 3 initial state values from the decoded acc triple. Circuits with `state_len < 3` fail at Nova::init with dimension mismatch. Modifying NovaCompressor's internal logic would risk breaking existing C7/CycloFold tests and violates the "do not modify NovaCompressor API" constraint.
- **Impact**: Third state element `step_index` increments by 1 each step, serving as a step counter consistent with C7DecryptAggregationCircuit's `step_count`.
- **Alternatives considered**: Modify NovaCompressor to handle variable state_len (rejected — too invasive for M1).

## Domain tag naming
- **Decision**: `PvssFoldVerifier` with byte literal `pvthfhe/p3/fold-verifier/v1`.
- **Rationale**: Follows existing PVSS tag naming convention; uses `p3/` namespace for P3-specific tags.
