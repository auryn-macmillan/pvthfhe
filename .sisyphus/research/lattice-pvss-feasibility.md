---
verdict: GoWithCaveat
spike_date: 2026-05-06
timebox_days: 5
---

# Lattice PVSS feasibility spike

## 1. Joint statement specification

### Existing in-repo Σ statement

`pvthfhe-nizk` already implements a Fiat-Shamir Σ-protocol for the RLWE relation

`d_i = c · s_i + e_i mod q`

with witness `(s_i, e_i)`, binary challenge `ch ∈ {0,1}^N`, and transcript absorption over `(t_rns, c_rns, d_rns, pvss_commitment)` under the locked domain separator `pvthfhe/cyclo-ajtai-d2/v1/` (`crates/pvthfhe-nizk/src/sigma.rs`, `fiat_shamir.rs`). The Ajtai commitment layer in `adapter.rs` commits to the packed witness and then embeds the sigma proof bytes into the single proof payload, so the current construction is already “Ajtai commitment + one Σ transcript + FS”.

### Composed PVSS statement

For recipient `j`, add a BFV share-encryption relation of the trBFV form from ePrint 2024/1285:

`(u_{ij}, v_{ij}) = BFV.Enc(pk_j, m = s_i; r_{ij})`

and keep the Hermine-style lattice PVSS viewpoint from ePrint 2025/901: a public vector commitment / proof-of-smallness statement tied to a linear encryption relation.

The joint public statement can therefore be written as

`X_{i,j} = (session_id, i, j, pk_j, c, d_i, C_i, u_{ij}, v_{ij}, q, N, B_e)`

with witness

`W_{i,j} = (s_i, e_i, r_{ij}, e^{enc,0}_{ij}, e^{enc,1}_{ij})`

such that all of the following hold simultaneously:

1. `d_i = c · s_i + e_i mod q`
2. `||e_i||_∞ ≤ B_e`
3. `C_i = SHA256(session_id || i_le || s_i_be)` (D2 hash binding already used in-repo)
4. `(u_{ij}, v_{ij})` is a valid BFV encryption of plaintext polynomial `s_i` under `pk_j` with randomness `r_{ij}` and bounded encryption noise.

Engineering conclusion for (a): **yes**, this remains amenable to a single Σ-protocol transcript, because the BFV encryption relation is another RLWE-linear relation. The prover can commit to masking terms for both the decrypt-share equation and the BFV encryption equation(s), absorb all public encodings into the existing transcript, and derive one common Fiat-Shamir challenge. No second transcript is forced by structure alone.

### Required code-surface changes

- Extend `NizkStatement` with per-recipient BFV public key / ciphertext fields.
- Extend `NizkWitness` with BFV encryption randomness and encryption-noise witnesses.
- Extend `sigma.rs` prove/verify equations to check the BFV encryption linear constraints alongside `d_i = c·s_i + e_i`.
- Extend `adapter.rs` proof encoding so the new BFV commitment/response material is part of the same proof blob and therefore the same FS challenge scope.

## 2. Prototype timing

### Measurement setup

- Canonical parameters: `N = 8192`, `log2_q = 174`, `B_e = 16` from `parameters.toml`.
- Toy prototype: one in-repo `CycloNizkAdapter` prove/verify on a single synthetic instance, used as a lower-bound proxy for the composed proof machinery.
- Baseline comparison source: `bench/results/fhe-baseline.md`, where the nearest available per-party keygen cost is `0.281600 s = 281.6 ms` at `n = 4, t = 3`.
- Acceptance threshold for condition (b), using that nearest baseline: `30 × 281.6 ms = 8448 ms`.

### Result

The crate-local feasibility test records wall-clock timing for one toy prove/verify run and prints it as `toy_prove_ms=... toy_verify_ms=...`. On the local spike run used for this note, prove time was comfortably sub-second and therefore well below the `≤ 8448 ms` proxy threshold implied by the nearest existing keygen-per-party benchmark.

Interpretation: **condition (b) is likely satisfied for a 1-instance toy lower bound**, but this is not yet a true `H=N=3` composed BFV+NIZK benchmark. Adding one BFV encryption relation per recipient will scale roughly linearly in the number of added RLWE equations and will also inflate proof bytes materially if full RNS ciphertexts are embedded naively.

## 3. Extractor argument review

The current repo deliberately exposes only a **conditional-soundness** claim. `pvthfhe-nizk` and the design spec both say the extractor argument (T2) is still a skeleton. For the current proof, the warning surface covers the existing Ajtai + RLWE share relation plus the D2 hash-binding check.

Composing in BFV share encryption changes that situation:

- the witness now couples `(s_i, e_i)` with fresh encryption randomness `r_{ij}` and encryption-noise terms,
- the verifier must accept an additional RLWE encryption statement tied to the same `s_i`, and
- a future extractor would need to extract a witness that opens **both** the decrypt-share relation and the BFV encryption relation consistently.

Conclusion for (c): **a fresh joint extractor argument would be required for any stronger formal claim**. The current conditional-soundness banner is directionally compatible with prototyping the composition, but it does **not** by itself close the new extraction obligation introduced by BFV share encryption. This is the main caveat.

## 4. Verdict

**Verdict: GoWithCaveat**

Why:

- **Go on structure**: the existing Sigma + Ajtai implementation can absorb BFV encryption validity into the same Fiat-Shamir Σ transcript; the algebra stays linear/RLWE-shaped.
- **Go on toy cost**: the current toy prove path is far below the nearest available `30× keygen-per-party` proxy bound.
- **Caveat on soundness scope**: the BFV composition widens the extractor obligation. The current conditional-soundness banner is enough for a feasibility spike, but not enough to say “no fresh extractor work is needed”.

Recommended follow-on before Phase P1:

1. Record the extra assumption / proof obligation in the assumptions ledger.
2. Implement a single-recipient composed prototype first, so proof-size and wall-time growth are measured before multiplying by all recipients.
3. Avoid naive full-RNS ciphertext embedding if proof size matters; hash-binding or compressed ciphertext encodings should be considered early.

## References

- ePrint 2025/901, *A Generic Framework for Practical Lattice-Based Non-interactive Publicly Verifiable Secret Sharing* — supports the “vector commitment + proof of smallness + linear encryption” framing for lattice PVSS.
- ePrint 2024/1285, *Robust Multiparty Computation from Threshold Encryption Based on RLWE* — supplies the threshold BFV / share-encryption context that motivates the per-recipient BFV statement.
