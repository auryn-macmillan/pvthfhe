# Security Theorems for PVTHFHE (Architecture B)

This document formalizes the security guarantees of the PVTHFHE protocol
(Architecture B: Lattice PVSS + LatticeFold+ + MicroNova). It systematically
maps the cryptographic properties required by the threshold FHE architecture to
specific cryptographic assumptions rigorously listed in the assumptions ledger.

Each section corresponds to one of the four critical pillars of the system's
security:
1. Confidentiality of encrypted data (T-IND-CPA)
2. Correctness of threshold decryption (T-DEC-SOUND)
3. Cryptographic soundness of on-chain verification (T-PV-SOUND)
4. Robustness and liveness of the protocol itself (T-ROBUSTNESS)

---

## T-IND-CPA: Confidentiality

**High-level intuition:** 
The protocol guarantees that the underlying encrypted data remains entirely
private, even if a sophisticated adversary has corrupted up to $t-1$ parties in
the network. The adversary is assumed to have full view of all public keys, all
ciphertexts broadcast over the network, and the internal state (including
partial shares and secret keys) of all the corrupted parties. Despite this
overwhelming visibility, the adversary cannot learn anything about the
underlying plaintext of an honest user's encryption.

**Formal statement:** 
Let $\lambda$ be the security parameter. Let $\mathcal{A}$ be a probabilistic
polynomial-time (PPT) adversary that statically corrupts a set of parties $S
\subset [N_{parties}]$ such that $|S| \le t-1$. We define the game
`IND-CPA-PV_B(\lambda, \mathcal{A})` as follows:
1. The challenger generates the public parameters and the common reference
string (CRS).
2. The challenger runs the distributed key generation (DKG) protocol, simulating
the honest parties and interacting with the adversary who controls the parties
in $S$. The result is an aggregate public key $pk$ and a set of secret shares.
3. The adversary $\mathcal{A}$ is given $pk$ and the secret shares of all
corrupted parties $i \in S$, as well as all transcript messages from the DKG
(including PVSS ciphertexts and NIZKs).
4. The adversary $\mathcal{A}$ outputs two equal-length messages $m_0, m_1$.
5. The challenger samples a random bit $b \gets \{0, 1\}$ and computes the
challenge ciphertext $ct^* \gets Encrypt(pk, m_b)$.
6. The adversary $\mathcal{A}$ is given $ct^*$ and outputs a guess $b'$.

The advantage of $\mathcal{A}$ is defined as $|Pr[b = b'] - 1/2|$. There exists
a negligible function $\epsilon(\lambda)$ such that for all such $\mathcal{A}$:
$$ Pr[\mathcal{A} \text{ wins IND-CPA-PV\_B}] \leq \frac{1}{2} +
\epsilon(\lambda) $$

**Assumption set:**
- `RLWE (Decision)`
- `Module-LWE`
- `Everywhere-Short Secret Sharing (Lattice-based VSS)`
- `PVSS-secrecy`
- `Smudging-lemma`

**Reduction sketch (ROM, transparent CRS):** 
This is a CPA game. There is no decryption oracle and no decryption-share step in the hybrid sequence. The adversary sees only public keys, the DKG transcript, and the challenge ciphertext.

1. **Hybrid 0 (Real game):** Adversary A sees honest-party public keys `{pk_i}_{i∉C}` and challenge ciphertext `ct* = Enc(pk, m_b)`.
2. **Hybrid 1.i (Replace honest PVSS shares, one party at a time):** Replace each honest party's PVSS encrypted shares with uniformly random elements in Rq. Indistinguishable by MLWE hardness (one reduction per honest party; security loss factor = n − |C|). The adversary controls fewer than t parties, so the threshold VSS guarantees the honest secret cannot be reconstructed.
3. **Hybrid 2 (Replace challenge ciphertext):** Replace `ct*` with an encryption of 0. Indistinguishable by RLWE hardness (one reduction). In this hybrid, the challenge ciphertext is independent of `m_b`.

In Hybrid 2, A's advantage is exactly 0. Therefore:
`Pr[A wins] ≤ 1/2 + (n − |C|) · ε_MLWE + ε_RLWE`

**Note on smudging:** The smudging lemma is not used in this hybrid sequence. It is relevant to the decryption protocol (T-DEC-SOUND), not to the CPA confidentiality game, because the CPA game does not include a decryption phase.

**Model:** 
Random Oracle Model (ROM). NIZKs are compiled via Fiat-Shamir in the ROM. No trusted setup is assumed; the CRS is transparent. The hybrid argument uses only MLWE and RLWE hardness assumptions. There is no decryption oracle in this CPA game — the hybrid sequence does not include any decryption-share step, and the smudging lemma is not invoked here.

**Tightness note:** Security loss factor = O(N_parties − |S|) from the per-party PVSS hybrid (Hybrid 1.i), plus ε_RLWE from the ciphertext replacement (Hybrid 2). No smudging term appears here — smudging is a decryption-protocol concern (T-DEC-SOUND), not a CPA-game concern.
**Cross-links:** 
- See `Round 1 — Share Distribution` (T18) for the PVSS generation algorithm.
- See `Per-party algorithm` (T19) for the generation of partial shares.

---

## T-DEC-SOUND

> ⚠️ CONDITIONAL THEOREM: This theorem assumes Open Problem P1 (lattice NIZK well-formedness soundness for folded RLWE) and Open Problem P2 (LatticeFold+ over RLWE folding argument) are resolved. Until then, this is a research conjecture, not a proved theorem.
: Decryption Soundness

**High-level intuition:** 
A malicious aggregator cannot trick the network or the verifier into accepting a
fake or maliciously manipulated decryption result. Even if the aggregator
completely controls all the corrupted parties and fabricates malformed partial
shares for them, it cannot forge an accepting SNARK proof for a plaintext that
is different from the true, mathematically derived encrypted message.

**Formal statement:** 
For all PPT adversaries $\mathcal{A}$, there exists a negligible function
$\epsilon(\lambda)$ such that the probability that $\mathcal{A}$ outputs a tuple
$(ct, m', \Pi_{SNARK})$ where $m'$ is not the correct decryption of $ct$, yet
the on-chain verifier accepts it, is bounded by:
$$ Pr[Verify(CRS, pk, m', \Pi_{SNARK}) = 1 \land m' \neq Dec(sk, ct)] \leq
\epsilon(\lambda) $$

**Assumption set:**
- `LatticeFold+-soundness`
- `MicroNova-binding`
- `NIZK-well-formedness (Open P1)`
- `LatticeFold+ over RLWE (Open P2)`

**Reduction sketch:** 
If an adversary $\mathcal{A}$ can forge an incorrect decryption proof, we
construct an efficient extractor $\mathcal{E}$ that breaks one of the underlying
assumptions.
Suppose the $Verify$ algorithm (defined in the `Public verifier algorithm` in
T19) accepts the proof $\Pi_{SNARK}$. By the `MicroNova-binding` property, the
acceptance of the SNARK proof implies knowledge of a valid, correctly folded
accumulator of constraints.
By the `LatticeFold+-soundness` assumption and its critical extension to
polynomial rings `LatticeFold+ over RLWE (Open P2)`, the correctly verified
accumulator definitively implies the existence of valid partial decryption
proofs $\pi_i^{dec}$ for at least $t$ individual shares (as defined in the
`Aggregator algorithm` in T19).
Furthermore, by the `NIZK-well-formedness (Open P1)` assumption, each of these
$t$ extracted shares is mathematically well-formed. That means the error
polynomial is genuinely short and the share is structurally bound to the
aggregate public key $pk$.
Crucially, since the decoding margin of the ciphertext is exceptionally wide
(156 bits as verified by the T21 noise budget analysis) and at least one honest
share must be included in any set of $t$ shares (since $|S| \le t-1$), the sum
of any $t$ validly proven shares cannot mathematically deviate enough to cause a
decoding failure to an incorrect $m'$. Thus, any successful forgery immediately
yields an extractor that produces a break of either the NIZK soundness or the
folding scheme's binding property.

**Tightness:** 
Tight reduction to the knowledge soundness of the LatticeFold+ scheme and the
MicroNova compression binding property.
**Model:** 
ROM / QROM (due to the use of the Fiat-Shamir heuristic required to make the
interactive folding and NIZK schemes non-interactive).
**Cross-links:** 
- See `Aggregator algorithm` (T19) for the folding constraints.
- See `Public verifier algorithm` (T19) for the on-chain checks.

---

## T-PV-SOUND: Public-Verifiability Soundness

**High-level intuition:** 
The final proof checking on the blockchain (or by any third-party verifier) is
cryptographically robust and entirely stateless. Anyone who successfully passes
the on-chain smart contract checks must have actually executed the honest
threshold aggregation mathematically over valid SNARKs; there is no shortcut or
bypass mechanism that allows a fake proof to be accepted.

**Formal statement:** 
For all PPT adversaries $\mathcal{A}$, there exists a negligible function
$\epsilon(\lambda)$ such that the probability $\mathcal{A}$ produces a valid
UltraHonk proof $\Pi_{SNARK}$ for a false statement (e.g., proving an incorrect
aggregation or bypassing threshold constraints) is bounded by:
$$ Pr[\text{Verifier accepts an invalid } \Pi_{SNARK}] \leq \epsilon(\lambda) $$

**Assumption set:**
- `KZG Polynomial Commitment (SDH)`
- `Random Oracle Model (ROM)`
- `QROM (Quantum Random Oracle Model)`

**Reduction sketch:** 
The on-chain verifier (`Public verifier algorithm` in T19) is implemented as a
standard UltraHonk SNARK verifier contract. Any adversary $\mathcal{A}$ capable
of producing a valid proof for a wrong threshold decryption statement directly
breaks the underlying SNARK knowledge soundness.
If $\mathcal{A}$ successfully forges such a proof, we can invoke the standard
UltraHonk knowledge extractor $\mathcal{E}_{UH}$. This extraction relies heavily
on the binding property of the `KZG Polynomial Commitment (SDH)` (for the BN254
elliptic curve circuit). If the adversary can open a commitment to two different
values or forge an evaluation proof, they can be used to construct a solver for
the q-Strong Diffie-Hellman problem.
The extensive use of the Fiat-Shamir transform to render the protocol
non-interactive strictly requires the `Random Oracle Model (ROM)`. Moreover,
ensuring post-quantum soundness for the threshold transcripts against quantum
adversaries analyzing the Fiat-Shamir hash requires the `QROM (Quantum Random
Oracle Model)`.

**Tightness:** 
Tight reduction directly to the KZG/UltraHonk algebraic knowledge soundness
bounds.
**Model:** 
ROM and QROM.
**Cross-links:** 
- See `Public verifier algorithm` (T19) for the exact steps verified on-chain.

---

## T-ROBUSTNESS

> ⚠️ CONDITIONAL THEOREM: This theorem assumes Open Problem P1 (lattice NIZK well-formedness soundness) is resolved.
: Abort-with-Public-Blame

**High-level intuition:** 
The distributed protocol is designed to be highly robust. If any participating
party cheats—whether by sending malformed keys, injecting invalid decryption
shares, or broadcasting bogus complaints—the protocol will reliably catch them.
The system will safely abort the current attempt and publicly flag the exact
cheater for penalization (such as on-chain slashing). Consequently, if there are
at least $t$ honest parties available, the protocol is guaranteed to eventually
complete successfully.

**Formal statement:** 
For all PPT adversaries $\mathcal{A}$ corrupting up to $t-1$ parties, there
exists a negligible function $\epsilon(\lambda)$ such that the probability the
protocol aborts without uniquely and correctly identifying a corrupted party as
the cause is bounded by:
$$ Pr[\text{Abort } \land \text{ No corrupted party is blamed}] \leq
\epsilon(\lambda) $$

**Assumption set:**
- `NIZK-well-formedness (Open P1)`

**Reduction sketch:** 
The blame matrix specifies 6 explicit failure modes (detailed exhaustively in
`Blame Matrix` in T18 and `Failure modes` in T19).
For a corrupted party to disrupt the protocol without being blamed, they must
successfully execute one of two strategies:
1. Submit a malformed share or key but successfully forge a valid NIZK proof
asserting its correctness.
2. Submit a valid cryptographic complaint against an honest party's perfectly
well-formed share.

By the `NIZK-well-formedness (Open P1)` assumption, forging a NIZK for an
invalid share occurs with an overwhelmingly negligible probability
$\epsilon(\lambda)$.
A malicious aggregator might attempt to drop honest shares, equivocate on the
aggregate output, or stall the protocol. However, the protocol specifies strict
timeout mechanisms ($\Delta_1, \Delta_2$) and exact mathematical verifications
(such as requiring any party to recompute the aggregate public key from the
participant set). These mechanisms allow any honest party to produce an
undeniable cryptographic proof of the aggregator's misbehavior (for example, by
publishing two conflicting `DecryptResult` messages signed by the aggregator).
Consequently, any protocol failure is deterministically traceable to a deviation
from the honest protocol execution, securely and publicly pinned to the
adversary, preventing anonymous denial-of-service.

**Tightness:** 
Tight reduction to the underlying NIZK soundness properties.
**Model:** 
ROM (for the Fiat-Shamir NIZKs used in complaints and proofs of misbehavior).
**Cross-links:** 
- See `Round 2 — Share Verification + Complaint` (T18) for keygen blame
mechanisms.
- See `Aggregator algorithm` (T19) for the decryption blame mechanisms.
