# Stage 1 Learnings

## [2026-05-04] Initialization

### Locked Constraints
- FHE backend: `gnosisguild/fhe.rs` (locked)
- Ring backend: `fhe-math` from same repo, rev `5f24d0b62a7329b789db07a065b68accd614a47b`
- Parameters: N=8192, log₂q≈174, B_e≈16 (6σ for σ=3.19)
- Design freeze: spec-real-p2p3.md §4.1 addendum selects BRANCH-B

### Key Public Inputs (7, from proof-boundary.md)
1. `ciphertext_hash` (bytes32 Keccak256)
2. `plaintext_hash` (bytes32 Keccak256)
3. `aggregate_pk_hash` (bytes32 Keccak256)
4. `dkg_root` (bytes32 Merkle root)
5. `epoch` (uint64)
6. `participant_set_hash` (bytes32 Keccak256)
7. `D_commitment` (bytes32 Keccak256)

### Stage 0 Preserved Invariants
- Stage 0 T2 build-time surrogate tripwire MUST survive Stage 1
- Stage 0 T3 opt-in mock policy (`PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1`) MUST survive Stage 1

### Forbidden Patterns
- No `#[allow]` suppressions
- No `nargo prove` / `nargo verify`
- No `cargo test --workspace`
- No `ConditionalSoundnessDisclosure` returning success
- No SHA-256 hash chain in production fold path
- No XOR-Merkle (must use Poseidon)
