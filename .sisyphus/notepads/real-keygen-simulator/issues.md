# Issues: real-keygen-simulator

## 2026-05-15 — None encountered
- Build and tests passed on first attempt after fixing `rand_chacha` dependency and removing unused `OsRng` import.

## R4: RED tests written — all 4 fail (2026-05-16)

### Test results
```
keygen_encrypt_not_stub: party 1 → recipient 2: encrypted_share is 2 bytes (stub?)
keygen_nizk_not_empty: party 1: NIZK is the empty fallback [0x00, 0x01]
keygen_nizk_verify_passes: party 1: NIZK proof count (0) != encrypted share count (3)
keygen_encrypt_structure: party 1: expected 5 NIZK proofs, got 0
```

### Root cause
`encrypt_share_for_recipient` returns `Err(_)` for all encryption attempts, triggering the fallback to `vec![0x11, 0x22]`. The likely cause:
- `run()` builds `all_pks` from `KeygenShare.bytes.0`, but those are keygen-share bytes (CRP + p0_share), NOT proper BFV public keys.
- When `FhersBackend::encrypt` receives malformed public key bytes, it fails.
- The NIZK field is `[0x00, 0x01]` because `nizk_proofs` is empty (all encryptions failed).

### Next steps
- R1-R3 implementation needs to fix public key construction in `run()`.
- After the public key fix, encryption should succeed and these 4 tests should turn GREEN.
