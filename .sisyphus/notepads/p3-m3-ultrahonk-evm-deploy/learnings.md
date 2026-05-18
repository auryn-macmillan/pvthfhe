# Learnings — P3-M3 UltraHonk EVM Deploy

## 2026-05-14

### Documentation created

Created `docs/security-proofs/p3/ultrahonk-deploy.md`, a deployment guide
for the UltraHonk EVM verifier contract.  The document records:

- **Source**: Aztec protocol `HonkVerifier.sol` (UltraHonk for BN254)
- **Target**: Sepolia testnet via Foundry
- **Gas projection**: ~39,687 (Aztec baseline)
- **BN254 precompiles**: 0x06-0x09
- **Status**: DEFERRED pending P3-M2 compression proofs
- **Policy**: External contract, pinned by commit hash, not shipped in repo

### Conventions followed

- Matched tone and structure of existing P3 docs (`theorem-inventory.md`,
  `proof-skeletons.md`)
- Table formatting for deployment target, precompile addresses, and gas
- Explicit deferral rationale documented, with checklist for when P3-M2
  delivers
- No em dashes, no AI slop phrases per project writing conventions

## 2026-05-16

### Status updated to DOCUMENTED

Updated `docs/security-proofs/p3/ultrahonk-deploy.md`: changed status from DEFERRED to
DOCUMENTED -- implementation deferred to post-p3-m2. No content changes to the deployment
plan itself; the document already contained the deployment target (Sepolia via Foundry),
Aztec protocol HonkVerifier.sol reference, and deferral rationale. Also updated the
meta-plan checkbox in `meta-plan-all-deferred.md` from `- [ ]` to `[-]` (documented,
implementation deferred).

### Meta-plan update

Changed checkbox for `p3-m3-ultrahonk-evm-deploy` in `.sisyphus/plans/meta-plan-all-deferred.md`
from unchecked (`- [ ]`) to documented/deferred (`[-]`).

## 2026-05-17

### Real proof verification achieved

Created `contracts/test/HonkVerifierRealProof.t.sol` — a Foundry test that feeds a real
(non-ZK) UltraHonk proof into `HonkVerifier.sol` and verifies it ACCEPTS.

**Key findings**:

1. **ZK vs non-ZK mismatch**: The proof originally on disk (generated with `bb prove
   --oracle_hash keccak`) was 8768 bytes (ZK flavor). The `HonkVerifier.sol` contract
   expects 7776-byte non-ZK proofs (`calculateProofSize(16) = 243 elements × 32 bytes`).
   Simply stripping bytes doesn't work because the ZK proof has a different internal
   layout (geminiMaskingPoly after pairing points, libraCommitments, 9-ary sumcheck
   round univariates instead of 8-ary).

2. **Regeneration fixed it**: Running `bb prove --verifier_target evm-no-zk` produced
   a 7776-byte proof that matches the verifier's expected format.

3. **VK hash matches**: The on-disk `vk_hash` at `circuits/aggregator_final/target/vk_hash`
   (`229bbce7633ca5ca124e329721f8185718aa95dcd5d76d1440b863edf516a465`) matches the
   contract's `VK_HASH` constant exactly.

4. **Public inputs**: 7 bytes32 values (224 bytes) from the `public_inputs` file.
   `NUMBER_OF_PUBLIC_INPUTS = 15`, `publicInputsSize - PAIRING_POINTS_SIZE = 7`.
   The public inputs are NOT direct Noir circuit parameters — they are hash commitments
   processed by BB's ACIR-to-Honk compilation. Only `epoch = 1` matches a
   `Prover.toml` value directly.

5. **Gas**: ~1.9M gas for successful verification. Well within 5M budget.

6. **bb version**: 5.0.0-nightly.20260517. The `--verifier_target` flag replaced
   the older `--oracle_hash` flag. `--verifier_target evm-no-zk` is required to
   produce proofs compatible with the non-ZK Solidity verifier.

**Test pattern**: Proof embedded as hex literal chunks (1024 bytes each) in
`bytes.concat()`. Public inputs as `bytes32[]` with explicit hex values aligned to
the `public_inputs` binary file.
