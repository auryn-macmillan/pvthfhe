---
status: frozen
version: 1
---

# PVSS Scheme Specification

> **GoWithCaveat**: This frozen PVSS statement is approved for Phase P1
> prototyping under the additional assumption recorded as
> `pvss-bfv-composition` in `.sisyphus/design/assumptions-ledger.md`.
> The composed Sigma+Ajtai + BFV-share-encryption transcript widens the
> extractor obligation beyond the current conditional-soundness banner;
> production use requires a joint extractor argument or a reduction closing
> that gap.

## sharing_relation:
s = Σ λ_i · s_i mod Φ_N(X)  with ‖s_i‖_∞ ≤ B_s

## per_recipient_encryption:
For each recipient j: (u_{ij}, v_{ij}) = BFV.Enc(pk_j, s_i; r_{ij})  with ‖r_{ij}‖_∞ ≤ B_r

## nizk_statement:
Prove knowledge of (s_i, {r_{ij}}_j) such that for each recipient j:
1. d_i = c · s_i + e_i mod q  (decrypt-share RLWE relation)
2. ‖e_i‖_∞ ≤ B_e
3. C_i = SHA256(session_id || i_le || s_i_be)  (D2 hash binding)
4. (u_{ij}, v_{ij}) is a valid BFV encryption of s_i under pk_j with randomness r_{ij}

Domain separator: "pvthfhe-pvss-share-encryption-v1"
FS hashing: reuses pvthfhe_nizk::fiat_shamir

## parameter_table:
Compatible with parameters.toml [rlwe]: N=8192, log2_q=174, B_e=16, B_s=1, B_r=TBD

## references:
- ePrint 2025/901 (Hermine): lattice PVSS framework
- ePrint 2024/1285 (trBFV): threshold BFV share-encryption context
