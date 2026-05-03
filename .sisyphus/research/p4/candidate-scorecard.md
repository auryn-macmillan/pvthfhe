# P4 Candidate Scorecard

This scorecard compares the three P4 construction candidates against the inherited constraints from A.R.1-A.R.4: post-quantum preference, public transcript verification, abort-with-blame, concrete scalability at \(n=1024\), BFV-key compatibility, and implementation tractability.

## Scoring rubric

- Scores use a 1-5 scale where 5 is best.
- **Assumption** prioritizes post-quantum security: lattice = 5, pairing = 2, discrete-log/DDH = 1.
- **Communication (n=1024)** follows the task rubric: \(O(n)\) = 5, \(O(n \log n)\) = 3, \(O(n^2)\) = 1.
- **Implementation Risk** is scored inversely: simpler and lower-risk integrations score higher.

## Candidate comparison

| Candidate | Assumption | Public Verifiability | Abort-with-Blame | Communication (n=1024) | BFV Integration | Implementation Risk | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Hermine-adapted (ePrint 2025/901) | 5 | 5 | 5 | 5 | 4 | 3 | 27 |
| SCRAPE + ZK-proof layer | 1 | 3 | 3 | 5 | 2 | 2 | 16 |
| Groth Non-interactive DKG + lattice encryption adapter | 2 | 5 | 2 | 5 | 2 | 1 | 17 |

## Candidate notes

### 1. Hermine-adapted (ePrint 2025/901)

- **Assumption — 5/5:** Hermine is the only candidate in the prior-art record that is already lattice-based and therefore aligned with the program's post-quantum requirement.
- **Public Verifiability — 5/5:** Public verifiability is native rather than retrofitted, matching the P4 transcript model in the threat model and theorem inventory.
- **Abort-with-Blame — 5/5:** The prior-art matrix identifies Hermine as the only surveyed line with native blame support, which directly supports P4-T4.
- **Communication (n=1024) — 5/5:** The candidate remains on the required \(O(n)\) publication path, so it stays viable at the target deployment size.
- **BFV Integration — 4/5:** It does not natively output BFV-format shares today, but its lattice witness and ciphertext structure are substantially closer to RLWE/BFV key material than the classical alternatives.
- **Implementation Risk — 3/5:** The main risk is adapting a generic lattice PVSS transcript into BFV-key-native share semantics without breaking the proof story.

### 2. SCRAPE + ZK-proof layer

- **Assumption — 1/5:** SCRAPE is DDH-based, so it is misaligned with the post-quantum requirement from the outset.
- **Public Verifiability — 3/5:** Base SCRAPE is publicly verifiable, but the full P4 requirement would depend on the added proof layer staying composable and auditable.
- **Abort-with-Blame — 3/5:** Blame is not native; a Sigma-proof or complaint layer could add accountability, but that pushes a core property into bolt-on machinery.
- **Communication (n=1024) — 5/5:** SCRAPE retains an \(O(n)\) sharing and verification profile, which is attractive for the scale target.
- **BFV Integration — 2/5:** The secret-sharing objects remain discrete-log flavored, so a BFV adapter would be a substantive semantic translation rather than a direct reuse.
- **Implementation Risk — 2/5:** This path combines assumption mismatch, a new blame layer, and a BFV adapter, so three major adaptations stack at once.

### 3. Groth Non-interactive DKG + lattice encryption adapter

- **Assumption — 2/5:** Groth's pairing-based foundation is cleaner than plain DDH for protocol structure, but it still misses the post-quantum target.
- **Public Verifiability — 5/5:** Non-interactive public verification is a native strength of the Groth line.
- **Abort-with-Blame — 2/5:** Robust public blame is not a native outcome here and would need to be layered on top of a pairing-based transcript.
- **Communication (n=1024) — 5/5:** The underlying construction preserves linear publication and therefore remains asymptotically acceptable.
- **BFV Integration — 2/5:** Wrapping a pairing-based PVSS/DKG transcript around lattice encryption still leaves a cross-algebra key-derivation gap.
- **Implementation Risk — 1/5:** This is the riskiest path because it couples a pairing transcript, a lattice wrapper, and a new accountability story in one design.

## Decision

**Primary Construction**: Hermine-adapted (ePrint 2025/901)
**Rationale**: Hermine-adapted is the only candidate that already matches the program's post-quantum, publicly verifiable, and abort-with-blame requirements at the protocol core. Its remaining gap is the BFV-key-output adaptation, but that gap is narrower and more researchable than retrofitting both post-quantum assumptions and blame into a classical scheme.

**Fallback Construction**: SCRAPE + ZK-proof layer
**Rationale**: SCRAPE is the best fallback because it preserves the desired linear-scale public transcript discipline and gives a credible classical baseline if the Hermine-to-BFV adaptation fails. It is inferior on assumptions and native accountability, but it is still more plausible than the pairing-wrapper route.

**Kill Criteria for Primary**: (1) the Hermine transcript cannot be mapped to BFV-key-native share semantics without introducing an unproved cross-algebra soundness gap; (2) the concrete proof or transcript constants appear non-viable for the \(n=1024\) target after cost modeling; (3) abort-with-blame cannot be preserved under the BFV adaptation without adding a qualitatively new proof system.
