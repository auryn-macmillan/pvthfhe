# P3RealVerifier Vacuity Audit — Summary

## Finding

`P3RealVerifier.sol` is a vacuous trusted-signer authenticator.  
It accepts **any** false FHE claim as long as the trusted signer endorses it.

## Hardcoded Signer Address

```
TRUSTED_SIGNER = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
```

Defined at `contracts/src/P3RealVerifier.sol:30-31`.

## Exact ecrecover Call Site

`contracts/src/P3RealVerifier.sol:63`

```solidity
bytes32 digest = keccak256(publicInputs);   // line 62
address recovered = ecrecover(digest, v, r, s); // line 63
return recovered != address(0) && recovered == TRUSTED_SIGNER; // line 65
```

## What Is NOT Verified

| Property | Verified? |
|---|---|
| FHE ciphertext correctness | NO |
| Threshold reconstruction validity | NO |
| NIZK / LatticeFold+ proof validity | NO |
| Consistency: ciphertext_hash <-> plaintext_hash | NO |
| Participant set honesty | NO |
| DKG root authenticity | NO |
| Any lattice-based property | NO |

## What IS Verified

Only one thing: the 65-byte secp256k1 ECDSA signature over `keccak256(publicInputs)` was produced by `TRUSTED_SIGNER`.

## Attack Scenario

An adversary controlling `TRUSTED_SIGNER`'s private key can:

1. Fabricate arbitrary `publicInputs` (false ciphertext hash, false plaintext hash, false epoch, etc.)
2. Sign `keccak256(falsePi)` with key `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`
3. Submit `(falseProof, falsePi)` — `verify()` returns `true`

## Evidence

- Test: `contracts/test/P3VacuityProof.t.sol::testVacuousVerifierAcceptsFalseClaim`
- Result: **PASS** (the verifier cannot reject the fabricated claim)
- Gas: 16,269 (well within 5M budget — ecrecover only)
- Log: `forge-output.log` in this directory

## Conclusion

`P3RealVerifier` is a placeholder / surrogate implementation (Option C per its own NatSpec).  
It satisfies the *interface* but provides zero FHE soundness guarantees.  
Any party with access to the trusted-signer private key can forge arbitrary decryption results on-chain.
