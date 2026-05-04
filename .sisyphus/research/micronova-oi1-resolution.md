# M1 OI-1 Resolution — Minimal MicroNova Prover Scaffold

## OI-1

Open Implementation-1 is the absence of a pinned, ready-to-consume MicroNova prover implementation in this repository for the P2→P3 bridge.

## Resolution for M1

M1 resolves OI-1 at the scaffolding level only:

- add a local workspace crate, `crates/pvthfhe-micronova`
- freeze a minimal API surface around `MicroNovaProver::prove(r1cs, witness)`
- keep the prover explicitly non-cryptographic by returning `MicroNovaError::Unimplemented`

This gives later tasks a stable Rust integration point without pretending that the BN254/Grumpkin MicroNova backend already exists.

## Why this is sufficient now

- `.sisyphus/research/micronova-digest.md` confirms that MicroNova is a BN254/Grumpkin IVC + compression stack, not a lattice-native backend.
- `.sisyphus/design/spec-real-p2p3.md §7.1` already freezes the high-level `MicroNovaAdapter` responsibilities: encode the final Cyclo accumulator as R1CS, prove the compressed statement, and serialize it for Noir.
- M1 is explicitly a scaffolding task; real proving logic is deferred to later M-tasks.

## Follow-on implementation plan

Later tasks should replace the stub in place by:

1. defining the concrete R1CS encoding for the final Cyclo accumulator
2. selecting and pinning the actual MicroNova proving backend (or equivalent implementation strategy) for the BN254/Grumpkin cycle
3. producing a compressed proof object consumable by the Phase-3 Noir wrapper
4. preserving the `MicroNovaProver::prove` entry point so downstream code does not churn

## Non-goals for M1

- no actual cryptography
- no backend selection claim beyond documenting the gap
- no Noir or Solidity integration
