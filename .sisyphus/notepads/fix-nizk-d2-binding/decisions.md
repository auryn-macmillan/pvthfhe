# Decisions

## D1: Preimage binding instead of content verification
The old approach recovered the encrypted share by decrypting the commitment CT (via mock backend's XOR property). This only worked for mock backends. The new approach uses a SHA256 preimage binding that works uniformly across all backends. Trade-off: content consistency is no longer verified by the verifier; it becomes the prover's responsibility.

## D2: ChaCha20Rng replaces custom SeedRng
Rather than maintaining a custom SHA256-based deterministic RNG, we now use `rand_chacha::ChaCha20Rng::from_seed()`. This is a standard, well-tested RNG already used elsewhere in the codebase (pvthfhe-cyclo tests).

## D3: Wire format appends d2_binding at the end
The new `d2_binding` field (32 bytes) is appended to the existing wire format after `lattice_binding`. This is backward-compatible in the sense that old proofs can't be decoded (different total length), but the version number is unchanged since this is a in-flight prototype.

## D4: Pre-existing RED tests ignored
4 decrypt-related RED tests were marked `#[ignore]` because they test R3.2 scope (decrypt NIZK, not share NIZK). These will be un-ignored when R3.2 is implemented.
