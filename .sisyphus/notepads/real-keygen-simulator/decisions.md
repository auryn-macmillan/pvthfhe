# Decisions: real-keygen-simulator

## D1: Deterministic keygen in simulator
- **Decision**: Use `ChaCha8Rng::from_seed(SHA256(session_id || party_id))` instead of `OsRng`
- **Rationale**: Single honest node controls all parties; deterministic keys let each dealer compute recipient public keys for encryption. Real deployments use independent randomness per party.
- **Tradeoff**: Not suitable for adversarial testing where keys must be independently random.

## D2: NIZK witness derivation
- **Decision**: Derive witness polynomial and error from plaintext via domain-separated SHA-256→ChaCha8Rng, matching the pattern in `demo_nizk.rs`
- **Rationale**: The `CycloNizkAdapter` requires a consistent (s, e) pair such that d = c*s + e. Using deterministically-derived witness ensures proofs verify while keeping the simulator self-contained.
- **Tradeoff**: The NIZK proves knowledge of a derivable witness rather than the actual BFV encryption witness. Upgrading to real witness requires `encrypt_with_witness` from the backend.

## D3: NIZK bundle format
- **Decision**: Serialize per-share NIZK proofs as `u16 count || for each: u32 len || proof bytes`
- **Rationale**: Round1Message has a single `nizk: Vec<u8>` field; bundling allows per-recipient proofs.
- **Tradeoff**: Not backward compatible with stub `vec![0x00, 0x01]` if consumed by external verifiers. Pipeline currently ignores nizk field (generates proofs separately via RealNizkAdapter).
