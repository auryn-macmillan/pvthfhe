# P4 Novelty Gap Memo for PVTHFHE

## 1. Context

PVTHFHE needs a threshold BFV key-generation path for up to 1024 parties in a post-quantum setting, so the underlying secret sharing and verification layer must be compatible with RLWE-style key material rather than only finite-field exponents. The target protocol also assumes zero trusted setup, public verifiability of dealer and participant behavior, and abort-with-blame so that malformed shares or openings leave a publicly attributable failure transcript. In this use case, asymptotic scalability matters twice: the parties must tolerate large-n deployments, and outside verifiers should not be forced into quadratic transcript checking just to validate one key-generation instance.

## 2. Gaps in Existing Schemes

### Feldman VSS

Feldman VSS gives a useful baseline for polynomial sharing, but it is neither publicly verifiable nor blame-capable in the PVTHFHE sense. Its commitments are discrete-log objects over finite-field secrets, so they do not naturally encode RLWE/BFV secret structure or BFV-format public-key outputs.

### Pedersen DKG / VSS

Pedersen-style DKG removes the trusted dealer, but it still inherits private verification and discrete-log commitments. For PVTHFHE, that leaves two critical holes: outsiders cannot validate correctness from the transcript alone, and the resulting secret-sharing relation is not tailored to RLWE public-key derivation.

### Gennaro-Jarecki-Krawczyk-Rabin DKG

GJKR improves dealer-free robustness, yet the matrix shows only partial blame support and no public verifiability. That means it does not close the accountability requirement for a public BFV key-generation ceremony, especially when an external verifier must distinguish honest aborts from malicious ones.

### Schoenmakers PVSS

Schoenmakers PVSS does provide public verifiability, but it remains anchored in ElGamal-style discrete-log encryption and does not provide abort-with-blame. For PVTHFHE, that prevents a direct lift to post-quantum RLWE shares and leaves failure attribution under-specified once decryption complaints begin.

### SCRAPE

SCRAPE is attractive because it keeps public verification efficient, but the matrix still marks it as non-blameable and only partially suitable for BFV-key derivation. In other words, SCRAPE improves scalable transcript checking without solving the structured-RLWE output problem needed for threshold BFV keys; see prior-art-matrix: SCRAPE.

### ALBATROSS

ALBATROSS pushes scalability further through batching and amortization, but its design goal is scalable randomness generation rather than RLWE key synthesis. The missing piece for PVTHFHE is that its compact public-verification path does not directly yield BFV-format public key material or an abort-with-blame story; see prior-art-matrix: ALBATROSS.

### FROST

FROST is important because it shows identifiable abort in a modern threshold setting, yet it is not a publicly verifiable PVSS/DKG scheme and still lives in prime-order discrete-log groups. Thus it supplies one accountability ingredient but not the public-auditability or RLWE key-generation interface that PVTHFHE needs; see prior-art-matrix: FROST.

### Practical Non-interactive PVSS with Thousands of Parties

The Gentry-Halevi-Lyubashevsky line is the closest classical-scale evidence that thousands-party PVSS can be made succinct, and it even uses lattice encryption. However, the matrix still lists only partial BFV suitability and no abort-with-blame, because the proof layer mixes assumptions and the output is not already BFV-format public-key material; see prior-art-matrix: Practical Non-interactive PVSS with Thousands of Parties.

### Groth Non-interactive DKG / PVSS

Groth gives a very clean non-interactive and dealer-free formulation, but it remains pairing based and oriented toward threshold BLS-style outputs. For PVTHFHE that means strong protocol structure without the post-quantum assumption set or RLWE-native output relation.

### Hermine

Hermine is the closest row to the target because it combines lattice assumptions, public verifiability, and abort-with-blame. Even so, the matrix describes only partial dealer-freeness and stops short of claiming a direct BFV public-key output interface, so a residual gap remains between generic lattice PVSS correctness and threshold BFV key-generation compatibility; see prior-art-matrix: Hermine.

## 3. Novelty Opportunities

### Opportunity 1 — Post-quantum publicly verifiable blame at 1024-party scale

**Gap description:** Existing public-verifiable schemes with good scalability, such as SCRAPE and ALBATROSS, are not post-quantum and do not offer abort-with-blame, while the closest lattice row (Hermine) does not yet establish the full large-n PVTHFHE target with compact public verification for n up to 1024; see prior-art-matrix: SCRAPE, see prior-art-matrix: ALBATROSS, see prior-art-matrix: Hermine.

**Rigor argument:** This is a real gap because the missing properties are not independent checkboxes: combining RLWE-compatible sharing, public transcript verification, and attributable abort requires one proof system and one message flow to witness all three simultaneously. The matrix shows no row that already dominates along all of those axes, so the gap is structural rather than merely editorial.

**Research direction:** In A.I.2, isolate which parts of the blame transcript and which parts of the public-verification proof can be expressed over lattice commitments without reintroducing pairings or discrete-log assumptions.

### Opportunity 2 — BFV-key-coupled share semantics

**Gap description:** The surveyed schemes overwhelmingly share discrete-log secrets or generic randomness, whereas PVTHFHE needs shares whose aggregation directly induces BFV/RLWE public-key material rather than a secret that must later be translated into a different algebraic form; see prior-art-matrix: Feldman VSS, see prior-art-matrix: Pedersen DKG / VSS, see prior-art-matrix: Hermine.

**Rigor argument:** This gap is non-trivial because RLWE public keys are structured tuples with distributional and noise constraints, not just arbitrary secrets hidden behind a commitment. A protocol that proves share consistency in one algebra but outputs keys in another can lose both soundness intuition and efficiency, so "just adapt the output" is not an adequate answer.

**Research direction:** In A.I.2, formalize what it means for a sharing relation to be BFV-key-native, including which public transcript invariants should imply correctness of the derived RLWE public key.

### Opportunity 3 — Concrete scalability beyond asymptotics

**Gap description:** Several rows advertise O(n) or amortized efficiency, but the matrix still indicates per-dealer ciphertext publication, verification work, or proof objects whose constants are tuned for different settings than a 1024-party BFV key ceremony; see prior-art-matrix: Schoenmakers PVSS, see prior-art-matrix: SCRAPE, see prior-art-matrix: Practical Non-interactive PVSS with Thousands of Parties.

**Rigor argument:** This gap is real because PVTHFHE cares about concrete verifier cost, not only asymptotic notation. A scheme can be asymptotically linear and still fail at n=1024 if each participant or public verifier must process large proofs, many ciphertext openings, or heavy non-native algebraic checks.

**Research direction:** In A.I.2, define a concrete cost model for 1024-party transcript size, prover work, and verifier work so candidate designs can be filtered before protocol-level construction begins.

### Opportunity 4 — Dealer-free RLWE accountability without trusted setup

**Gap description:** Dealer-free DKG rows such as Pedersen, GJKR, Groth, and FROST each capture some combination of robustness or blame, but none combine dealer-freeness, post-quantum assumptions, public verifiability, and RLWE-native outputs in a single no-setup package; see prior-art-matrix: Pedersen DKG / VSS, see prior-art-matrix: Gennaro-Jarecki-Krawczyk-Rabin DKG, see prior-art-matrix: Groth Non-interactive DKG / PVSS.

**Rigor argument:** The difficulty is substantive because removing the dealer while keeping public auditability forces every participant contribution to be publicly checkable and composable under adversarial scheduling. In lattice settings, that requirement interacts with ciphertext size, proof aggregation, and reconstruction semantics in ways that classical discrete-log DKG analyses do not settle.

**Research direction:** In A.I.2, separate the minimal accountability interface needed for a dealer-free RLWE key-generation round from the stronger features that can be deferred to later optimization work.

## 4. Non-Goals

- We are not claiming that no useful PVSS/DKG literature exists; the claim is narrower: no listed row already satisfies the full PVTHFHE package of post-quantum assumptions, public verifiability, abort-with-blame, zero trusted setup, and BFV-native output semantics.
- We are not claiming a concrete construction in this memo. The point here is to isolate the novelty gap, not to specify commitments, ciphertext layouts, or proof systems.
- We are not claiming asymptotic impossibility for classical schemes. The claim is instead that adapting them to RLWE/BFV and public blame at 1024-party scale would require new technical work rather than straightforward instantiation.
- We are not claiming that Hermine is insufficient in general; only that, as represented in the matrix, it does not yet close the entire BFV-coupled and dealer-free PVTHFHE target.
