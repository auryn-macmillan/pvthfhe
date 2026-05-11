DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY

This repository contains critical cryptographic surrogates that provide no real security:
- no on-chain cryptographic verification — verifier accepts any proof bytes
- Noir circuits are tautological surrogates (assert(x == x) — no real constraints)
- do not use for The Interfold or any production deployment

See SECURITY-ADVISORY-001.md and SECURITY.md for details.
