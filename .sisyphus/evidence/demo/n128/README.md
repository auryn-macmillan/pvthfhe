# Demo Walkthrough: n=128 e2e

## Command

```
cargo run --release -p pvthfhe-cli -- demo --n 128 --seed 1
```

## Pipeline Steps

### Step 1: Keygen
- 128 parties run distributed key generation via `KeygenSimulator`
- Threshold: 65 (n/2+1)
- All 3 rounds complete without blame
- Aggregate public key produced (sk material never logged)

### Step 2: Encrypt
- Plaintext: `hello pvthfhe!`
- Encrypted under aggregate public key using `MockBackend`
- RNG seeded with `--seed 1` for determinism

### Step 3: Partial Decrypt
- Each of 128 parties produces a `DecryptSharePayload`
- Each party uses a deterministic per-party RNG (`seed XOR party_id`)
- 128 shares collected

### Step 4: Aggregate Decrypt
- `aggregate_decrypt` combines all 128 shares (threshold=65)
- Plaintext round-trip verified: `OK`

### Step 5: Folding
- `FoldingAccumulator` accumulates all 128 `PartyProof` entries
- `finalize()` produces a `FinalSnark` (hash-chain surrogate)
- Proof size: 32 bytes

## Result

```
verify: ACCEPT
```

## Determinism

Two runs with `--seed 1` produce identical stdout output (modulo ANSI log timestamps).
The key outputs (`aggregate_pk_hash`, `ciphertext_hash`, `snark_proof_hash`) are identical across runs.

## Key Hashes (seed=1, n=128)

- `aggregate_pk_hash`: `df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119`
- `ciphertext_hash`: `8666cab5e3c4f411d1fdea87cf26ce6a3cfc58f28993715d02671bde3c29a48c`
- `snark_proof_hash`: `53b46cdd3731d65d92c38c3abb7ed852290016075cd7381b3c100348cddcc666`
