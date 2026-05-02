# Architecture C: Hybrid Noir Wrapper + Recursive Aggregation

## Overview
Architecture C proposes a hybrid Noir wrapper combined with recursive UltraHonk aggregation. In this design, we wrap each party's partial-decryption proof directly into a Noir circuit (bypassing lattice-native folding schemes) and recursively aggregate $N$ such proofs using UltraHonk recursion (`std::recursion::verify_proof`). The final output is a single on-chain verifiable proof.

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

### IND-CPA-PV_C Game
```
Experiment IND-CPA-PV_C(\lambda, \mathcal{A}):
1. Setup(1^\lambda) \to CRS, pp
2. KeyGen(CRS) \to (pk, \{(sk_i, \pi_i)\}_i)
3. \mathcal{A}(pk, \{\pi_i\}) \to (m_0, m_1, S) where |S| < T_{thresh}
4. b \gets\$ \{0,1\}; ct^* \gets Encrypt(pk, m_b)
5. \mathcal{A}(ct^*, \{sk_i\}_{i \in S}) \to b'
Win if b = b' and all \pi_i verify
```
*Research Open Problem:* Recursive UltraHonk soundness under adaptive proof composition is not formally proven in the BB/Noir literature. The security reduction here strictly relies on the KZG binding assumption and the AGM.

## Algorithms

### 1. Setup
```
Algorithm Setup(1^\lambda) -> (CRS, pp)
[OUTSIDE NOIR]
1. Generate KZG-based UltraHonk CRS for BN254. 
2. Sample common random polynomial a \gets\$ R_q
3. Return pp = (N, q, t, \chi_{key}, \chi_{err}), CRS
```

### 2. KeyGen
```
Algorithm KeyGen(CRS, pp) -> (pk, {(sk_i, \pi_i)}_{i=1}^{N_{parties}})
[OUTSIDE NOIR]
1. For each party i \in [1, N_{parties}]:
   a. Sample s_i \gets\$ \chi_{key} and e_i \gets\$ \chi_{err}
   b. Compute pk_i = (a, b_i) where b_i = a \cdot s_i + e_i \pmod q
   c. Optional: generate lightweight Schnorr-style PoK for s_i (no ZK proof at keygen natively)
2. Aggregate public key: pk = (a, \sum b_i \pmod q)
3. Return (pk, \{(s_i, \pi_i)\})
```

### 3. Encrypt
```
Algorithm Encrypt(pk, m) -> ct
[OUTSIDE NOIR]
1. Sample u, e_0, e_1 \gets\$ \chi_{err}
2. Encode plaintext m into \Delta m
3. ct_0 = b \cdot u + e_0 + \Delta m \pmod q
4. ct_1 = a \cdot u + e_1 \pmod q
5. Return ct = (ct_0, ct_1)
```

### 4. PartialDecrypt
```
Algorithm PartialDecrypt(ct, sk_i, CRS) -> (d_i, \pi_i)
[OUTSIDE NOIR]
1. Compute partial decryption d_i = ct_1 \cdot s_i + e_i \pmod q
[NOIR-CIRCUIT BOUNDARY: entering leaf circuit `rlwe_partial_dec`]
2. Prove knowledge of sk_i such that d_i = ct_1 \cdot s_i + e_i \pmod q (RLWE relation check)
3. Apply range proofs on error e_i
4. Produce UltraHonk proof \pi_i
[NOIR-CIRCUIT BOUNDARY: exiting leaf circuit]
5. Return (d_i, \pi_i)
```

### 5. Aggregate
```
Algorithm Aggregate(\{d_i\}_{i \in S}, \{\pi_i\}_{i \in S}, ct_0) -> (m', \Pi)
[OUTSIDE NOIR]
1. Require |S| \ge T_{thresh}
2. Compute combined mask: d_S = \sum_{i \in S} \lambda_{i,S} d_i \pmod q
3. m_{noisy} = ct_0 - d_S \pmod q
4. m' = Round(m_{noisy})
[NOIR-CIRCUIT BOUNDARY: entering aggregation circuit]
5. For i in 1..|S|:
   a. Execute std::recursion::verify_proof(\pi_i)
6. Ensure \lambda_{i,S} coefficients are well-formed and combined correctly
7. Produce single aggregated UltraHonk proof \Pi
[NOIR-CIRCUIT BOUNDARY: exiting aggregation circuit]
8. Return (m', \Pi)
```

### 6. Verify
```
Algorithm Verify(CRS, pk, m', \Pi) -> {0, 1}
[NOIR-CIRCUIT BOUNDARY: On-chain Solidity verifier]
1. Run BB-generated UltraHonk verifier on proof \Pi
2. Check public inputs match aggregated constraints and m'
3. O(1) EVM gas check (approx 200k-500k gas)
4. If valid, return 1; else return 0
```

## Risk Register & Novelty Callouts
- **Risk 1:** O(N) Aggregation Circuit Size limit. The aggregation circuit grows linearly with $N_{parties}$. At $N=1024$, recursive verify calls could result in 10M-50M gates, which may be infeasible for Barretenberg to prove within reasonable RAM/time constraints.
- **Risk 2:** Unproven Composition Soundness. The recursive UltraHonk soundness under adaptive proof composition is not formally proven in the BB/Noir literature. The security reduction relies on KZG binding and AGM heuristics.
- **Novelty 1:** Direct Noir Implementation Bypassing Lattice Folding. By directly evaluating the RLWE relation in a Noir circuit and utilizing standard UltraHonk recursion, we eliminate the need for exotic lattice folding schemes, drastically reducing complexity at the cost of aggregator compute.
