# MicroNova Heterogeneous IVC — Soundness Argument

**Theorem ID**: P3-MN1  
**Status**: skeleton  
**Plan**: `.sisyphus/plans/micronova-heterogeneous-ivc.md`

---

## Statement

**Theorem P3-MN1 (Heterogeneous IVC Soundness Preservation).** Let
`CF` be a `HeterogeneousCircuitFamily<Fr>` with `n = CF.num_circuits()`
deterministic circuit variants, and let `HeterogeneousStepCircuit<CF>`
be the dispatcher step circuit that routes each step `i` to
`CF.circuit_index(i)`. If each individual circuit variant `j ∈ {0, …, n-1}`
is sound under the underlying Sonobe Nova folding scheme (i.e., any
accepting IVC proof with step circuit `j` implies existence of a valid
witness trace for that circuit), then the heterogeneous compressor
`MicroNovaCompressor` using `HeterogeneousStepCircuit<CF>` preserves
soundness: any accepting heterogeneous proof implies existence of a valid
witness trace with the correct circuit variant at each step.

Formally, for all PPT adversaries `A`:

```
Pr[ MicroNovaVerify(vk, π, steps) = 1
    ∧ ¬∃ valid trace matching CF.circuit_index(i) at each step i ]
    ≤ n · ε_nova
```

where `ε_nova` is the soundness error bound of the underlying Sonobe Nova
scheme (see P2 soundness budget, `.sisyphus/design/fold-soundness-budget.md`).

---

## Proof Technique

Hybrid argument over circuit variants. Each circuit variant `j` in the
family has a distinct verifier key commitment `CF.circuit_hash(j)`. The
heterogeneous step circuit binds `circuit_index(i)` at each step, preventing
an adversary from using circuit `j` at a step where `j' ≠ j` is expected.

**Step 1 — Verifier key separation.** The `HeterogeneousStepCircuit`
derives distinct `StepCircuit::circuit_hash()` outputs for each circuit
variant via `CF.circuit_hash(j)`. The Sonobe verifier key commits to
the step circuit hash, binding each variant to a distinct `vk_j`.

**Step 2 — Deterministic dispatch.** The function `CF.circuit_index(i)`
is a deterministic total function of the step number `i`. The verifier
reconstructs the same dispatch table and checks each step against the
correct `vk_j`.

**Step 3 — Hybrid reduction.** Suppose an adversary produces an
accepting heterogeneous proof with an invalid trace at some step `i*`.
Let `j* = CF.circuit_index(i*)`. Construct `n` hybrids where hybrid `j`
replaces circuit `j` with a soundness challenger. By the union bound,
the adversary's advantage against the heterogeneous scheme is at most
`n` times the advantage against the hardest circuit variant.

---

## Reduction Target

Sonobe Nova soundness over the BN254/Grumpkin cycle (see P2 soundness
budget and `.sisyphus/design/fold-soundness-budget.md`). The heterogeneous
wrapper introduces at most a factor-`n` tightness loss from the union
bound over circuit variants.

---

## Circuit Family for LatticeFold+

For `LatticeFoldTreeCircuitFamily` with depth `d`:

- `n = 2` (leaf ring-equation verifier at level 0, internal fold verifier at levels 1..d)
- Leaf count: `2^d`
- Total IVC steps: `2^(d+1) - 1`

The union-bound tightness loss is `n = 2`, which is constant and negligible
relative to the underlying Nova soundness margin.

---

## Unresolved Lemmas

- **L1 (Nova step-circuit isolation)**: That the Sonobe Nova scheme's
  soundness composes across distinct step circuits sharing the same
  state structure (state_len = 3, ExternalInputs3). Formal proof requires
  analysis of the Nova accumulation scheme's commitment binding across
  circuit variants.

---

## Open Questions

1. Does the Sonobe `Nova::verify` path separately validate the step-circuit
   hash against the verifier key for each step, or does it assume a
   single-circuit model? If the latter, the hybrid argument's Step 1
   requires an explicit check in `MicroNovaCompressor::verify_tree`.
2. Can the union-bound factor `n` be eliminated via a direct reduction
   that leverages the circuit family's deterministic dispatch without
   per-circuit hybrid game hops?
