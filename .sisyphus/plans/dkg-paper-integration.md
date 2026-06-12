# Plan: DKG Paper (2026/1159) Integration into pvthfhe

**Status**: draft → pending Momus review
**Paper**: Abraham, Bacho, Stern — *Quadratic Asynchronous DKG from Plain Setup* (2026/1159)
**Paper location**: `~/paper/2026-1159.md`; reference copy to be placed at `docs/papers/2026-1159.md`
**Date**: 2026-06-10
**Scope**: Integrate techniques T1–T4 and T6 from the paper. Skip T5 (aggregatable lattice PVSS — open research problem).

---

## 1. Techniques to Integrate

| ID | Technique | Paper Section | Target Component | Effort |
|----|-----------|---------------|------------------|--------|
| **T1** | Non-Equivocation Protocol | §4.1, Algorithms 7–8 | DKG Round 1 binding | Low |
| **T2** | PVSS Exchange (committee-based sharing) | ABLS25 reference, §4.2 | DKG share distribution | High |
| **T3** | Provable AVID (Disperse + PrivateRetrieve) | §4.3, Algorithms 11–13 | Encrypted share dispersal | Medium-High |
| **T4** | Key Escrow → Distributed Key Authorization | §6, Algorithms 3–5 | Decryption authorization | Medium |
| **T6** | Weak Leader Election → Aggregator Selection | §7, Algorithm 6 | Aggregator selection | Medium |

### Why each technique matters for pvthfhe

- **T1 (Non-Equivocation)**: `spec-keygen.md` line 55 already lists equivocation as a blame mode, but no cryptographic mechanism exists to prove it. Fills a documented gap.
- **T2 (Committee-based sharing)**: Current DKG broadcasts to all n parties → O(n²) Shamir generation bottlenecks at n≥150 (ARCHITECTURE.md:121). Committee sampling reduces to O(λn).
- **T3 (Provable AVID)**: Current shares are broadcast-encrypted per-recipient. AVID enables efficient dispersal with succinct verification — each party stores only their share, not all n shares.
- **T4 (Key Escrow)**: Strengthens partial decryption authorization — the aggregator must prove escrow without learning decryption keys until f+1 parties authorize.
- **T6 (Aggregator Selection)**: Aggregator is currently permissionless (anyone can run it). Leader selection provides predictable, retroactively-verifiable aggregator identity, preventing targeted pre-computation attacks.

---

## 2. Design — What Changes

### 2.1 Non-Equivocation Protocol (T1)

**Current state**: Parties broadcast Round 1 messages. If a party sends two different Round 1 messages, other parties "see two msgs with same dealer_id" (blame matrix row 3), but there is no cryptographic proof.

**Target state**: After Round 1 message broadcast, each party runs a NonEquiv round:
- Each party collects signatures from ≥ n-f parties on their Round 1 message
- **NonEquiv proof** = collection of n-f signatures with quorum intersection guarantee
- Anyone can verify: two valid NonEquiv proofs for different messages from the same dealer = cryptographic evidence of equivocation
- Instantiated with **lattice signatures** (Falcon-512) — no EC assumptions, compatible with the PQ boundary

**Design decisions**:
- Signature scheme: Falcon-512 (NIST PQC standardized, lattice-based)
- Quorum size: n-f (matching the paper's quorum intersection guarantee)
- Proof structure: `NonEquivProof { signatures: Vec<NonEquivSignature>, message_hash: [u8; 32] }`
- Domain separator: `"pvthfhe-non-equiv-v1"`
- **MPC-AUDIT-2026-06-12 (F1)**: Schnorr signatures in NonEquiv now bind `session_id` in `hash_to_challenge`, `hash_round1_message`, and `non_equiv_challenge`. This prevents cross-session replay. See `.sisyphus/audit/MPC-AUDIT-2026-06-12.md` §F1.

### 2.2 PVSS Exchange / Committee-Based Sharing (T2)

**Current state**: Each dealer generates n encrypted shares (one per recipient) and broadcasts all of them. Communication is O(n²) in share bytes.

**Target state**: Each dealer sends PVSS transcripts to only Θ(λ) parties (λ ≈ 128). Committee selection uses a VRF-derived permutation.

**Design decisions**:
- Committee size: `k = max(λ, t)` where λ=128 security parameter
- Selection mechanism: 
  - Input seed: permutation of `session_id || prevrandao()` (Ethereum `block.prevrandao` when available, or `session_id` for offline testing)
  - VRF: Use SHA-256 as random oracle → `party_index = SHA256(seed || dealer_id || cmt_idx) % n`
  - Committee members are publicly verifiable from the seed
- Aggregation: Committee members forward their PVSS transcripts to all parties. Each party verifies ≥ k-t+1 transcripts.
- **No pairing-based aggregatable PVSS** — this is protocol-level committee selection, not cryptographic transcript aggregation

**Backward compatibility**: Committee mode is feature-gated (`feature = "committee-pvss"`). Default remains full broadcast. Demo-e2e can test both modes.

### 2.3 Provable AVID (Disperse + PrivateRetrieve) (T3)

**Current state**: Dealer encrypts and broadcasts all n shares individually. Each recipient decrypts only their share but receives all n ciphertexts.

**Target state**: Dealer disperses data with a Merkle-based commitment (succinct proof). Each party privately retrieves only their assigned share. Anyone can verify correct dispersal.

**Design decisions**:
- **Encoding**: Use the existing `shamir.rs` Shamir secret sharing as the dispersal code (already Reed-Solomon-equivalent over BN254 Fr)
- **Commitment**: Poseidon Merkle tree over shares (reuse existing Poseidon R1CS from `C7MerkleStepCircuit`)
- **Disperse proof**: Merkle root + Poseidon path proofs per share
- **Retrieve protocol**: Each party requests their share from the disperser; disperser returns share + Merkle path proof
- **Public verifiability**: Merkle root is broadcast; any party can verify share correctness against root
- **Private retrieval**: Share is encrypted under recipient's BFV public key before dispersal (reuse existing `encrypt.rs` BFV encryption)

**Integration**: Replace `EncryptedShares` broadcast with `DispersedShares { merkle_root, proofs }`. Existing NIZK share-encryption proofs are preserved — they now operate on encrypted shares retrieved via AVID.

### 2.4 Key Escrow → Distributed Key Authorization (T4)

**Current state**: Partial decryption requires t honest parties, but there is no authorization layer. Anyone who holds a party's share can submit partial decryptions.

**Target state**: Each decryption epoch has an escrowed authorization key. The aggregator must:
1. Request decryption authorization from ≥ f+1 parties
2. Receive escrowed key shares
3. Reconstruct the authorization key
4. Prove authorization before partial decryptions are accepted

**Design decisions**:
- Escrow scheme: Encrypt authorization key under aggregate public key → only recoverable with f+1 partial decryptions
- This maps directly to pvthfhe's existing threshold decryption: the "authorization" IS a threshold decryption of the escrowed key
- Each decryption epoch generates a fresh ephemeral key pair:
  - `eph_pk = Σ pk_i` (aggregation of per-party ephemeral keys)  
  - `eph_sk` is threshold-shared (Lagrange reconstruction)
- Authorization flow:
  1. Aggregator publishes decryption request with epoch tag
  2. ≥ f+1 parties respond with `PartialDecrypt(eph_ct, i)` where `eph_ct = Encrypt(eph_pk, session_id)` 
  3. Aggregator reconstructs `eph_sk` = proof of authorization
  4. Aggregator submits `eph_sk` with decryption proof on-chain

**Note**: The `prevrandao()` seed from Ethereum can serve as the epoch tag for on-chain decryption requests, providing non-malleable epoch binding.

### 2.5 Weak Leader Election → Aggregator Selection (T6)

**Current state**: Aggregator is permissionless — anyone can submit aggregation proofs. The Interfold design uses Ethereum's `prevrandao()` as a pseudorandom seed for per-request randomness.

**Target state**: A weak leader election protocol selects one honest aggregator with constant probability (α ≥ 1/3, matching the paper's guarantee). The selected aggregator's identity is retroactively verifiable.

**Design decisions**:
- **Phase 1 — Rank generation**: Each party generates a `ProvableRank` → `(rank_i, π_rank_i)` where rank is derived from `Hash(PartialCoin(eph_vk, (party_id, tag)))` 
- **Phase 2 — Leader determination**: Leader = party with highest rank (or hash of rank if tied). Identical to the paper's Phase 4.
- **Rank derivation**: Use existing `session_id || prevrandao_permutation` as the tag. This ties leader election to an on-chain random seed, preventing pre-computation.
- **Retroactive verification**: Anyone can verify `RankVerify(party_id, rank, π, tag)` to confirm the elected leader was honestly selected.
- **Integration with existing flow**: The elected leader becomes the designated aggregator for this epoch. If the leader fails to produce a proof within timeout, fall back to permissionless mode.

**Important caveats**:
- This is a **weak** leader election (α-correctness): with constant probability, an honest party is selected. The remaining probability may select a corrupt party or produce disagreement.
- In the paper, this is sufficient because the ADKG consensus protocol re-tries on disagreement. In pvthfhe's synchronous model, we can re-run the election or fall back.
- The paper's full Protocol 6 requires Key Escrow + ProvableRank, which in turn requires PVSSExchange + aggregated PVSS. We adapt:
  - Instead of bilinear-group PVSS, we use the existing lattice PVSS for rank commitment
  - Instead of Key Escrow, we use a simpler commit-reveal: parties commit to ranks in Round 1, reveal in Round 2
  - This is less communication-efficient but compatible with the lattice-only constraint

---

## 3. Implementation Tasks

### Phase A: Foundation (T1 + supporting infrastructure)

| Task | Description | Crates affected |
|------|-------------|----------------|
| **A.1** | Add `pvthfhe-non-equiv` crate with `NonEquivProof` type, Falcon-512 signature integration | new crate |
| **A.2** | Add `NonEquivRound` to `KeygenSimulator` in aggregator: after Round 1 broadcast, collect signatures | `pvthfhe-aggregator` |
| **A.3** | Add `EquivocationEvidence` type to `spec-keygen.md` blame matrix | `pvthfhe-keygen-spec` |
| **A.4** | Add Falcon-512 keypair generation to `PartyIdentity` | `pvthfhe-keygen` |
| **A.5** | Add adversarial tests: equivocation detection, NonEquiv proof verification | `pvthfhe-aggregator/tests/adversarial/` |

### Phase B: Provable AVID (T3)

| Task | Description | Crates affected |
|------|-------------|----------------|
| **B.1** | Add `DispersedShares` type with Merkle root and Poseidon path proofs | `pvthfhe-pvss` |
| **B.2** | Implement `disperse()` in `LatticePvssBfvAdapter`: Shamir-encode encrypted shares, build Merkle tree, output root + per-party proofs | `pvthfhe-pvss` |
| **B.3** | Implement `retrieve_share()`: verify Merkle path + decrypt share | `pvthfhe-pvss` |
| **B.4** | Replace `EncryptedShares` broadcast in `KeygenSimulator` Round 1 with `DispersedShares` + private retrieval | `pvthfhe-aggregator` |
| **B.5** | Add Merkle path verification tests | `pvthfhe-pvss/tests/` |

### Phase C: Committee-Based Sharing (T2)

| Task | Description | Crates affected |
|------|-------------|----------------|
| **C.1** | Add `committee_sample(session_id, n, k, seed)` function using SHA-256-based VRF | `pvthfhe-pvss` |
| **C.2** | Implement committee-mode PVSS: dealer sends to only k parties, committee forwards | `pvthfhe-pvss` |
| **C.3** | Feature-gate behind `committee-pvss` feature flag | `pvthfhe-pvss/Cargo.toml` |
| **C.4** | Add `--committee` flag to demo-e2e and per-node binaries | `pvthfhe-cli` |
| **C.5** | Add scaling comparison tests: full broadcast vs committee mode at n=64,128 | `pvthfhe-bench` |

### Phase D: Key Escrow / Authorization (T4)

| Task | Description | Crates affected |
|------|-------------|----------------|
| **D.1** | Add `KeyEscrowSession` type: ephemeral key pair, escrowed secret, authorization proofs | `pvthfhe-pvss` |
| **D.2** | Implement escrow flow: `escrow(session_id) → (eph_pk, π_escrow)`, `authorize(eph_pk) → PartialDecrypt`, `reconstruct_key(shares) → eph_sk` | `pvthfhe-pvss` |
| **D.3** | Wire authorization into `Aggregator` decrypt flow: aggregator must prove authorization before partial decryptions are accepted | `pvthfhe-aggregator` |
| **D.4** | Add authorization tests: honest + malicious paths | `pvthfhe-aggregator/tests/adversarial/` |

### Phase E: Aggregator Selection (T6)

| Task | Description | Crates affected |
|------|-------------|----------------|
| **E.1** | Add `ProvableRank` type and `RankVerify` function using existing Ajtai NIZK + SHA-256 hash chain | `pvthfhe-pvss` |
| **E.2** | Implement `WeakLeaderElection` protocol: commit ranks → reveal → select max | `pvthfhe-aggregator` |
| **E.3** | Add `--elect-leader` flag to demo-e2e: before aggregation, run leader election | `pvthfhe-cli` |
| **E.4** | Wire `prevrandao()`-derived seed into leader election tag | `pvthfhe-aggregator` |
| **E.5** | Add leader election tests: honest majority, corrupt minority, tie-breaking | `pvthfhe-aggregator/tests/adversarial/` |

### Phase F: Documentation

| Task | Description | Files |
|------|-------------|-------|
| **F.1** | Update `README.md`: add DKG paper integration section to Open Problems, update Status table | `README.md` |
| **F.2** | Update `ARCHITECTURE.md`: add NonEquiv, AVID, committee mode, escrow, leader election to protocol layers | `ARCHITECTURE.md` |
| **F.3** | Update `SECURITY.md`: add Falcon-512 assumption, NonEquiv security argument, leader election threat model | `SECURITY.md` |
| **F.4** | Update `WARNING.md`: note new features are research-stage | `WARNING.md` |
| **F.5** | Add design docs for each technique: `spec-non-equiv.md`, `spec-avid.md`, `spec-committee-pvss.md`, `spec-key-escrow.md`, `spec-leader-election.md` | `.sisyphus/design/` |
| **F.6** | Update `spec-keygen.md`: add NonEquiv round, committee mode, AVID dispersal | `.sisyphus/design/spec-keygen.md` |
| **F.7** | Update `dkg-construction.md`: add paper as Candidate 4, comparison matrix | `.sisyphus/design/dkg-construction.md` |
| **F.8** | Update `assumptions-ledger.md`: add Falcon-512 signature assumption, leader election assumptions | `.sisyphus/design/assumptions-ledger.md` |
| **F.9** | Update `interfold-equivalence.md`: map new components to Interfold C0-C7 | `.sisyphus/design/interfold-equivalence.md` |
| **F.10** | Copy paper to `docs/papers/2026-1159.md` with attribution header | `docs/papers/2026-1159.md` |
| **F.11** | Update `AGENTS.md`: add paper reference, new crate | `AGENTS.md` |

### Phase G: Justfile & Integration

| Task | Description | Files |
|------|-------------|-------|
| **G.1** | Add `just non-equiv-test` recipe: run NonEquiv + equivocation detection tests | `Justfile` |
| **G.2** | Add `just committee-demo` recipe: demo-e2e with committee mode | `Justfile` |
| **G.3** | Add `just leader-elect-demo` recipe: demo-e2e with leader election | `Justfile` |
| **G.4** | Add `just avid-test` recipe: AVID dispersal + retrieval tests | `Justfile` |
| **G.5** | Add `just dkg-paper-gate` recipe: runs all new tests + validates paper reference | `Justfile` |
| **G.6** | Verify all existing Just recipes still pass (`test-all`, `demo-e2e`, `pvss-gate`, `wire-gate`, `adversarial-suite`) | `Justfile` |

---

## 4. Dependency Graph

```
Phase A (T1: NonEquiv) ───────────────┐
                                       ├── Phase D (T4: Key Escrow) depends on T1 NonEquiv for proof structure
Phase B (T3: Provable AVID) ──────────┤
                                       ├── Phase C (T2: Committee PVSS) depends on T3 AVID for dispersal
Phase A + B ──────────────────────────┘
                                       │
Phase A + B + D ──────────────────────┼── Phase E (T6: Leader Election) depends on T1, T4 for ProvableRank + escrow
                                       │
All Phases ───────────────────────────┼── Phase F (Documentation)
                                       │
All Phases ───────────────────────────┼── Phase G (Justfile + Integration)
```

**Execution order**: A → (B, D in parallel) → C → E → F → G

---

## 5. Success Criteria

1. **NonEquiv**: Two different Round 1 messages from same dealer produce verifiable equivocation evidence. NonEquiv proofs verify for honest parties.
2. **Provable AVID**: Encrypted shares are disbursed via Merkle tree; each party retrieves only their share. Merkle path verification passes.
3. **Committee PVSS**: At n=64 with committee mode produces identical aggregate key to full broadcast mode. Communication reduced.
4. **Key Escrow**: Decryption requires f+1 authorizations. Unauthorized decryption attempts are rejected. Epoch replay is prevented.
5. **Leader Election**: With honest majority, leader is honest with probability ≥ 1/3. Disagreement is detected and handled (fallback to permissionless).
6. **All existing gates pass**: `test-all`, `demo-e2e`, `pvss-gate`, `wire-gate`, `adversarial-suite`, `stage0-gate` all pass without regression.
7. **Documentation**: All F.1–F.11 docs updated. Paper copied to `docs/papers/`.

---

## 6. Non-Goals

- **T5 (Aggregatable lattice PVSS)**: Requires novel lattice construction — out of scope.
- **Asynchronous network model**: pvthfhe assumes synchronous rounds. Not adapting to asynchronous model.
- **Adaptive adversary**: Paper's model is strongly adaptive (erasure model). pvthfhe remains static malicious.
- **Full ADKG protocol**: Only the building blocks are integrated, not the complete asynchronous DKG.
- **On-chain leader election verification**: Leader election runs off-chain with retroactive verifiability. On-chain enforcement is P4-deferred.
- **Production deployment**: All new features are research-stage only. DO-NOT-DEPLOY banner remains.

---

## 7. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Falcon-512 integration complexity | Medium | Medium | Use `pqc-falcon` crate; if blocked, fall back to Schnorr (non-PQ but acceptable for research prototype) |
| Merkle tree overhead in AVID | Low | Low | Poseidon is already integrated; tree depth ~13 for n≤8192 |
| Committee sampling breaks threshold | Low | High | Verify committee size ≥ t mathematically; test at boundary conditions |
| Leader election α < 1/3 in practice | Medium | Low | Accept lower α; fall back to permissionless mode |
| Justfile recipe breakage | Low | Medium | Test all recipes after each phase |

---

## 8. Evidence Requirements

Each phase completion requires:
- `lsp_diagnostics` clean on all changed files
- `cargo test --workspace` passes (or targeted crate tests)
- New adversarial tests in `pvthfhe-aggregator/tests/adversarial/`
- Phase-specific gate recipe passes

---

## References

- Abraham, Bacho, Stern — *Quadratic Asynchronous DKG from Plain Setup* (2026/1159)
- ABLS25 — Abraham, Bacho, Loss, Stern — Asynchronous DKG with committee-based PVSS
- BL23 — Bacho, Loss — Aggregatable PVSS security
- GJKR99 — Gennaro, Jarecki, Krawczyk, Rabin — Secure DKG (EUROCRYPT 1999)
- Pedersen 1991 — Non-interactive VSS
