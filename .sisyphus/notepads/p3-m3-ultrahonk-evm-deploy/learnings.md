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
