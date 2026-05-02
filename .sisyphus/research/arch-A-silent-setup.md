# Architecture A: Silent-Setup PV-ThFHE

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

### IND-CPA-PV_A Game
```
Experiment IND-CPA-PV_A(\lambda, \mathcal{A}):
1. Setup(1^\lambda) \to CRS, pp
2. KeyGen(CRS) \to (pk, \{(sk_i, \pi_i)\}_i)
3. \mathcal{A}(pk, \{\pi_i\}) \to (m_0, m_1, S) where |S| < T_{thresh}
4. b \gets\$ \{0,1\}; ct^* \gets Encrypt(pk, m_b)
5. \mathcal{A}(ct^*, \{sk_i\}_{i \in S}) \to b'
Win if b = b' and all \pi_i verify
```

### Decryption-Soundness Game
An adversary cannot produce a valid proof $\pi_i'$ for an incorrect partial decryption $d_i' \neq d_i$.

### Public-Verifiability Game
Any external party can verify the correctness of the threshold key generation and the partial decryptions using only public information (CRS, aggregate $pk$, and proofs $\{\pi_i\}$).

## Algorithms

### 1. Setup
```
Algorithm Setup(1^\lambda) -> (CRS, pp)
1. Generate transparent or KZG-based CRS for NIZKs/SNARKs
2. Sample common random polynomial a \gets\$ R_q
3. Return pp = (N, q, t, \chi_{key}, \chi_{err}), CRS
```

### 2. KeyGen
```
Algorithm KeyGen(CRS, pp) -> (pk, {(sk_i, \pi_i)}_{i=1}^{N_{parties}})
1. For each party i \in [1, N_{parties}]:
   a. Sample s_i \gets\$ \chi_{key} and e_i \gets\$ \chi_{err}
   b. Compute pk_i = (a, b_i) where b_i = a \cdot s_i + e_i \pmod q
   c. Generate NIZK proof \pi_i for knowledge of (s_i, e_i) with short norms
2. Aggregate public key: pk = (a, \sum b_i \pmod q)
3. Return (pk, \{(s_i, \pi_i)\})
```

### 3. Encrypt
```
Algorithm Encrypt(pk, m) -> ct
1. Sample u, e_0, e_1 \gets\$ \chi_{err}
2. Encode plaintext m into \Delta m
3. ct_0 = b \cdot u + e_0 + \Delta m \pmod q
4. ct_1 = a \cdot u + e_1 \pmod q
5. Return ct = (ct_0, ct_1)
```

### 4. PartialDecrypt
```
Algorithm PartialDecrypt(ct, sk_i, CRS) -> (d_i, \pi_i^{dec})
1. Sample smudging noise f_i \gets\$ \chi_{smudge} (variance \gg ||ct_1 \cdot e_i||)
2. Compute partial decryption d_i = ct_1 \cdot s_i + f_i \pmod q
3. Generate NIZK proof \pi_i^{dec} proving correct relation of d_i with pk_i and ct_1
4. Return (d_i, \pi_i^{dec})
```

### 5. Aggregate
```
Algorithm Aggregate(\{d_i\}_{i \in S}, ct_0) -> m'
1. Require |S| \ge T_{thresh}
2. Compute combined mask: d_S = \sum_{i \in S} \lambda_{i,S} d_i \pmod q
   (where \lambda_{i,S} are Lagrange interpolation coefficients)
3. m_{noisy} = ct_0 - d_S \pmod q
4. Return m' = Round(m_{noisy})
```

### 6. Verify
```
Algorithm Verify(CRS, \{pk_i, \pi_i\}_{i=1}^{N_{parties}}, \{d_i, \pi_i^{dec}\}_{i \in S}) -> {0, 1}
1. For i \in [1, N_{parties}], verify KeyGen proof \pi_i
2. For i \in S, verify PartialDecrypt proof \pi_i^{dec}
3. If all proofs are valid, return 1; else return 0
```

## Open Problems
1. **Smudging Noise Bound:** Establishing a precise variance for smudging noise $f_i$ that satisfies the $120$-bit statistical indistinguishability while preserving correct decoding bounds for $N=8192$.
2. **Lagrange Interpolation Over Rings:** Handling the non-invertibility of evaluation points modulo $q$ in the RLWE setting when dynamically aggregating a subset $S$ (may require lifting to $\mathbb{Z}$ or special evaluation points).
3. **NIZK Overhead:** Ensuring the NIZK proofs $\pi_i$ and $\pi_i^{dec}$ do not bottleneck the EVM verifier. May require a recursive SNARK layer wrapping all $\pi_i$ into a single $\Pi$.

## Risk Register
- **Risk 1:** Naive aggregation of proofs causes $O(n)$ gas scaling which hits the block gas limit before $n=1024$.
  - *Mitigation:* Employ SNARK folding or recursion off-chain to submit a single aggregated proof.
- **Risk 2:** KnLWE attacks (e.g., PS25, ePrint 2024/1984) reduce actual security bits if smudging noise interacts with threshold access structures.
  - *Mitigation:* Ensure $f_i$ standard deviation is chosen carefully under the most recent lattice attacks, or avoid additive smudging by using non-interactive zero-knowledge proofs for exact Gaussian noise.
- **Risk 3:** L-BFV robustness relies on interactive protocols which are at odds with silent-setup.
  - *Mitigation:* Use NIDKG via 2025/901 to simulate the trusted dealer non-interactively.
