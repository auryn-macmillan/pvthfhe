# AGENTS.md

## Intent

PVTHFHE targets private-verifiable threshold FHE: O(n) per-party work with O(polylog n) verifier cost.

## Layout

- `research/` and `.sisyphus/research/`: experiments and provenance
- `design/` and `.sisyphus/design/`: architecture notes and scripts
- `crates/`: Rust workspace crates
- `circuits/`: Noir workspace and packages
- `contracts/`: Foundry project
- `bench/`: benchmark assets and scripts
- `docs/`: project documentation
- `.sisyphus/`: plans, evidence, scripts, notepads

## Gates

- `just phase1-gate`
- `just phase2-gate`
- `just phase3-gate`

## TDD policy

Always write a RED test before every implementation change.

## Draft vs plan

- Plans live in `.sisyphus/plans/` and are read-only.
- Draft work belongs in notepads and implementation files.

## FHE backends

Allowed backends are Poulpy or `gnosisguild/fhe.rs`; final choice is deferred to T4.

## Stub protocol

Replace stubs in place. Never delete and recreate a stub file.

## Working-directory protocol

- Foundry: run `forge ... --root contracts` from repo root
- Noir: run `(cd circuits && nargo ...)` from repo root
- Cargo: run from repo root with `-p <crate>` when targeting a crate

## Toolchain install protocol

- Rust: `rustup` using the channel from `rust-toolchain.toml`
- Foundry: `foundryup`
- Noir: `noirup`
- Barretenberg bb CLI: `bbup`
- Pin exact versions in `REPRODUCING.md` in T44

## Canonical Noir + BB flow

1. `nargo execute --package <pkg> --prover-name <Prover_name>`
2. `bb write_vk --scheme ultra_honk -b target/<pkg>.json -o target`
3. `bb prove --scheme ultra_honk -b target/<pkg>.json -w target/<pkg>.gz -o target`
4. `bb verify --scheme ultra_honk -k target/vk -p target/proof -i target/public_inputs`

Forbidden: `nargo prove`, `nargo verify`.
