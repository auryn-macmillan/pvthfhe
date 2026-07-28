# circuits/ — Noir workspace

Zero-knowledge circuits for the PVTHFHE on-chain verification path (P3/P4).
Build and test with the canonical flow from AGENTS.md
(`nargo execute` → `bb write_vk` → `bb prove` → `bb verify`;
`nargo prove`/`nargo verify` are forbidden).

## Packages

| Package | Proves | Used by |
|---|---|---|
| `protocol_constants` | (library) shared Q modulus + domain tags | other packages |
| `decrypt_share` | R3 partial-decryption share correctness, Poseidon-bound | `just noir-onchain-gate` |
| `aggregator_final` | C7 threshold-decryption correctness (Lagrange recombination via Schwartz-Zippel) | `just noir-onchain-gate`, `just circuit-param`; witness written by the cli pipeline |
| `nova_state_commitment` | IVC state binding for on-chain verification | `just noir-onchain-gate`, `just verify-onchain` |
| `ajtai_commitment` | Ajtai commitment + fold-step (P4 on-chain decider) | `just ajtai-onchain-gate` |
| `ivc_verifier` | UltraHonk-wrapped IVC verifier | `just demo-e2e` |
| `bench/rlwe_relation` | toy RLWE bench relation | `bench/scripts/reproduce.sh` |
| `decider_wrapper` | Per-channel LatticeFold+ terminal accumulator verification (field-element digests, no N=256 ceiling) | `feat/native-per-channel` (Phase 3, future on-chain decider) |

## Checked-in `target/` artifacts

`decrypt_share/target/` and `nova_state_commitment/target/` contain
checked-in proof/vk/public_inputs. They are load-bearing inputs for
`just verify-onchain` (bb verify) and for the Foundry tests
(`contracts/foundry.toml` fs_permissions reads them). Regenerate them via
`just noir-onchain-gate` rather than editing by hand. All other `target/`
directories are untracked build output.
