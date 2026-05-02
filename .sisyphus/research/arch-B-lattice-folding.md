# Architecture B: Lattice PVSS + Folding + MicroNova

This architecture replaces pairing-based setups with a lattice-native PVSS (no pairings) for share distribution. It aggregates per-party share-correctness proofs via a folding scheme (LatticeFold+ / Lova) and then compresses the final folded instance into a Noir-verifiable SNARK via MicroNova for cheap on-chain verification.

## Notation
- $n$: ring dimension ($N=8192$ for secure params, $\approx 120$-bit security)
- $q$: ciphertext modulus (product of $L=3$ RNS primes, $\approx 174$ bits)
- $t$: plaintext modulus
- $\chi_{key}$, $\chi_{err}$: key and error distributions
- $R_q = \mathbb{Z}[X]/(X^N+1, q)$
- $sk = (s_1,\dots,s_{N_{parties}}) \in R_q^{N_{parties}}$ (committee secret keys)
- $pk = (a, b) \in R_q^2$: aggregate public key
- $ct = (ct_0, ct_1) \in R_q^2$: ciphertext
- $N_{parties}$: committee size (target $n=1024$)
- $T_{thresh}$: reconstruction threshold $= \lfloor N_{parties}/2 \rfloor + 1$

## Security Games

### IND-CPA-PV_B Game
```
Experiment IND-CPA-PV_B(\lambda, \mathcal{A}):
1. Setup(1^\lambda) \to CRS, pp
2. KeyGen(CRS) \to (pk, \{(sk_i, \pi_i)\}_i)
3. \mathcal{A}(pk, \{\pi_i\}) \to (m_0, m_1, S) where |S| < T_{thresh}
4. b \gets\$ \{0,1\}; ct^* \gets Encrypt(pk, m_b)
5. \mathcal{A}(ct^*, \{sk_i\}_{i \in S}) \to b'
Win if b = b' and the folded SNARK proof verifies on-chain.
```
*Research Open Problem:* lattice NIZK for hint well-formedness is an open subproblem — the soundness of folding over RLWE requires a new argument. We cannot assume folding "just works" over RLWE without a soundness argument.

## Algorithms

### 1. Setup
```
Algorithm Setup(1^\lambda) -> (CRS, pp)
[FOLD-VS-SNARK BOUNDARY]: In the lattice IOP world
1. Generate transparent CRS for lattice PVSS (based on RLWE hardness, no pairings)
2. Sample common random polynomial a \gets\$ R_q
3. Return pp = (N, q, t, \chi_{key}, \chi_{err}), CRS
```

### 2. KeyGen
```
Algorithm KeyGen(CRS, pp) -> (pk, {(sk_i, \pi_i)}_{i=1}^{N_{parties}})
[FOLD-VS-SNARK BOUNDARY]: In the lattice IOP world (native Rust, no SNARK constraints)
1. For each party i \in [1, N_{parties}]:
   a. Sample s_i \gets\$ \chi_{key} and e_i \gets\$ \chi_{err}
   b. Compute pk_i = (a, b_i) where b_i = a \cdot s_i + e_i \pmod q
   c. Generate lattice NIZK \pi_i proving well-formedness of share.
2. Aggregate public key: pk = (a, \sum b_i \pmod q)
3. Return (pk, \{(s_i, \pi_i)\})
```

### 3. Encrypt
```
Algorithm Encrypt(pk, m) -> ct
[FOLD-VS-SNARK BOUNDARY]: In the lattice IOP world
1. Sample u, e_0, e_1 \gets\$ \chi_{err}
2. Encode plaintext m into \Delta m
3. ct_0 = b \cdot u + e_0 + \Delta m \pmod q
4. ct_1 = a \cdot u + e_1 \pmod q
5. Return ct = (ct_0, ct_1)
```

### 4. PartialDecrypt
```
Algorithm PartialDecrypt(ct, sk_i, CRS) -> (d_i, \pi_i^{dec})
[FOLD-VS-SNARK BOUNDARY]: In the lattice IOP world
1. Compute partial decryption d_i = ct_1 \cdot s_i + f_i \pmod q
2. Generate lattice proof \pi_i^{dec} (proving the RLWE relation)
3. Return (d_i, \pi_i^{dec})
```

### 5. Aggregate (fold + compress)
```
Algorithm Aggregate(\{d_i\}_{i \in S}, ct_0) -> (m', \Pi_{SNARK})
1. Compute combined mask: d_S = \sum_{i \in S} \lambda_{i,S} d_i \pmod q
2. m_{noisy} = ct_0 - d_S \pmod q
3. m' = Round(m_{noisy})
[FOLD-VS-SNARK BOUNDARY]: In the folding accumulator (LatticeFold+ / Lova)
4. Fold N party proofs \{\pi_i^{dec}\} into a single accumulator \Pi_{fold} (O(log N) rounds, O(1) per-fold work amortized)
[FOLD-VS-SNARK BOUNDARY]: In the Noir/BB SNARK (BN254 circuit)
5. Compress the final folded instance \Pi_{fold} into a Noir/BB UltraHonk proof \Pi_{SNARK} via MicroNova
6. Return (m', \Pi_{SNARK})
```

### 6. Verify
```
Algorithm Verify(CRS, pk, m', \Pi_{SNARK}) -> {0, 1}
[FOLD-VS-SNARK BOUNDARY]: On-chain (Solidity)
1. UltraHonk verifier checks the single compressed SNARK \Pi_{SNARK} (O(1) gas, independent of N)
2. Return 1 if SNARK verifies, else 0
```

## Cost Table

| N (Parties) | Per-Party Work | Verifier Work | Proof Size | On-chain Gas |
|-------------|----------------|---------------|------------|--------------|
| 64          | ~32 gates      | O(1)          | ~14KB      | ~200k-500k   |
| 128         | ~64 gates      | O(1)          | ~14KB      | ~200k-500k   |
| 256         | ~128 gates     | O(1)          | ~14KB      | ~200k-500k   |
| 512         | ~256 gates     | O(1)          | ~14KB      | ~200k-500k   |
| 1024        | ~512 gates     | O(1)          | ~14KB      | ~200k-500k   |

## Risk Register & Novelty Callouts
1. **Folding Soundness (Novelty/Risk):** lattice NIZK for hint well-formedness is an open subproblem — the soundness of folding over RLWE requires a new argument. We cannot assume folding "just works" over RLWE without a soundness argument.
2. **Lova vs LatticeFold+ (Risk):** Do not conflate Lova with LatticeFold. Lova is for linear relations, while LatticeFold+ is for R1CS. Choosing the wrong folding scheme for the RLWE relation will break soundness or efficiency.
3. **MicroNova Compression (Novelty):** Compressing a lattice folding accumulator into a BN254 SNARK via MicroNova crosses a highly experimental algebraic boundary. The gap between Lattice IOP and Noir SNARK could introduce encoding overheads negating the O(1) gas benefits.
