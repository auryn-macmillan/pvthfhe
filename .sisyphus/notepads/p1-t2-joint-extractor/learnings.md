# Learnings — P1-T2 Joint Extractor

## M1: Forking-Lemma Formalization

### 2026-05-14

- **Ternary challenge space is the bottleneck.** The small |C| = 3 makes the Pointcheval-Stern forking-lemma bound vacuous for any ε_acc < 1 when Q_total ≥ 4. The standard bound gives ε_extract ≈ ε_acc²/Q_total - ε_acc/3, which is negative for Q_total = 12 and any ε_acc ≤ 1. This is a known limitation of the Pointcheval-Stern lemma with small challenge spaces, not a mistake. The actual extraction guarantee must come from M-SIS reduction (M2), not the forking lemma alone.

- **Two competing bound formulations.** The task specification uses ε_acc² without the Q_total denominator (idealized model where extractor knows which ROM query to rewind at). The standard forking lemma includes ε_acc²/Q_total. The document presents both and notes that the idealized bound is tighter (~0.65 at ε_acc=0.99) while the standard bound is vacuous. The discrepancy should be resolved in M2 when the extraction probability is recomputed under the M-SIS reduction.

- **Multi-layer ROM overhead is linear, not multiplicative.** Each additional layer adds O(Q_i/|C|) overhead to the forking-lemma loss. For |C| = 3, this is significant (~1.33 per ROM query) but does not multiply with the quadratic ε_acc² term. The composition is additive, not a product of individual extraction probabilities.

- **SHA-256 binding avoids commitment-layer rewinding.** The Ajtai commitment layer does not need separate forking-lemma extraction because the extractor can verify consistency between the extracted witness and the commitment via SHA-256 preimage check. If they don't match, it's a SHA-256 collision. This simplifies the joint extractor: only the RLWE relation layer needs rewinding.

- **Parameter bounds for Δ = ±2 need M3.** The inverse of 2 in Z_{q_commit}[X]/(X^256 + 1) has norm ~2^49, which would blow up the extracted witness norm. Lemma 9 guarantees invertibility but not norm boundedness. The question of whether Δ = ±2 extraction is sound at these parameters needs the M3 challenge-space analysis.
