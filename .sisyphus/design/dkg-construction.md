# R1.0 DKG Construction Draft

Status: **draft — recommended pending oracle review**.

Scope: compare three DKG constructions for PVTHFHE's BFV threshold pipeline.

Non-scope: implementation, wire-format edits, circuits, Solidity, or plan updates.

---

## Context

PVTHFHE needs DKG to create a BFV threshold key for `n` parties and a `t`-of-`n`
decryption threshold.

The generated artefacts must include an aggregate BFV public key, per-party
threshold secret shares, and public transcript data.

The transcript must bind into the on-chain verifier via `dkg_root` and
`participant_set_hash`.

Citation: `.sisyphus/design/spec-real-p2p3.md` lines 50–64 define the seven
public inputs, including `dkg_root` and `participant_set_hash`.

The existing keygen spec assumes parties `P_1..P_n`, threshold
`t = floor(n/2)+1`, static malicious adversaries, abort-with-public-blame, and
timeout-based rounds.

Citation: `.sisyphus/design/spec-keygen.md` lines 13–18.

The construction must replace the current toy DKG, whose audit findings include
GF(256) sharing, deterministic reshare randomness, deterministic encryption
randomness, missing smudging, and no real ceremony.

Citation: task context cites F6, F20, F21, F23, F27, F28, and F60–F63 in
`.sisyphus/audit/AUDIT-2026-05-08.md`.

The FHE backend is locked to `gnosisguild/fhe.rs` and `fhe-math`.

Citation: `AGENTS.md` Backend Lock and `.sisyphus/design/spec-real-p2p3.md`
§4.1 addendum.

The canonical BFV/RLWE parameters are `N=8192`, three 58-bit NTT-friendly RNS
limbs, `log2(Q)≈174`, plaintext modulus `2^17`, and a small key distribution.

Citation: `.sisyphus/design/parameters.md` lines 13–25 and 48–61.

The local backend stores party secret material as coefficient vectors and as an
optional `fhe_math::rq::Poly`.

Citation: `crates/pvthfhe-fhe/src/fhers.rs` lines 31–40.

The local backend converts those coefficients / polynomials into decryption-share
polynomials through `ShareManager`.

Citation: `crates/pvthfhe-fhe/src/fhers.rs` lines 157–215.

The upstream `fhe::bfv::SecretKey` is a BFV-parameter-bound coefficient vector,
not a BN254 scalar.

Citation: docs.rs `fhe/bfv/keys/secret_key.rs` lines 20–25 define
`SecretKey { par: Arc<BfvParameters>, coeffs: Box<[i64]> }`.

Upstream `SecretKey::random` samples a vector of coefficients and `new` constructs
a key from coefficients.

Citation: docs.rs `fhe/bfv/keys/secret_key.rs` lines 42–52.

Upstream decryption converts those coefficients into `fhe_math::rq::Poly`.

Citation: docs.rs `fhe/bfv/keys/secret_key.rs` lines 211–218.

Therefore a sound DKG should either share the BFV ring object natively or prove a
translation from another field into that object.

This draft recommends the native BFV/RLWE route.

---

## Candidates

### Candidate 1 — Pedersen-DKG over RLWE / threshold FHE

#### Protocol sketch

Each dealer samples a BFV secret polynomial `s_i` and the public-key-share noise
needed by the fhe.rs multi-party BFV interface.

The common public polynomial is session-derived and already represented locally
as `CommonRandomPoly`.

Citation: `crates/pvthfhe-fhe/src/fhers.rs` lines 74–80.

Each dealer publishes a BFV public-key share compatible with `PublicKeyShare`.

Citation: `crates/pvthfhe-fhe/src/fhers.rs` lines 435–445 call
`PublicKeyShare::new_extended`.

Each dealer also secret-shares its BFV secret polynomial across recipients.

Shares may be represented coefficient-wise over CRT limbs or as ring elements,
but the reconstructed object must be the fhe.rs BFV secret coefficient vector.

Citation: `crates/pvthfhe-fhe/src/fhers.rs` lines 258–339 show the current
degree-by-RNS share aggregation shape.

Receivers verify encrypted/private shares and public proof material, then sum all
valid received shares into their final threshold secret share.

Citation: `.sisyphus/design/spec-keygen.md` lines 19–40 already uses share
distribution, verification/complaint, and aggregation rounds.

The public proof should bind the dealer public-key share to a short BFV secret
and bounded noise in the same ring relation as BFV.

Citation: `.sisyphus/design/spec-pvss.md` lines 16–29 and
`.sisyphus/design/spec-real-p2p3.md` lines 70–112 define related RLWE witness
relations.

#### Paper citation

The threshold-FHE lineage is Asharov, Jain, and Wichs, ePrint 2011/613,
"Multiparty Computation with Low Communication, Computation and Interaction via
Threshold FHE".

Citation: IACR ePrint 2011/613 metadata and PDF table of contents list Section 4
"Threshold Fully Homomorphic Encryption".

The DKG/VSS lineage includes Pedersen 1991 and Gennaro-Jarecki-Krawczyk-Rabin
EUROCRYPT 1999.

Citation: Springer page for Gennaro et al. lists title, authors, pages 295–310,
and DOI 10.1007/3-540-48910-X_21.

#### Secret-sharing field

Native sharing domain is `R_q = Z_q[X]/(X^N+1)` or its CRT/RNS decomposition.

Citation: `.sisyphus/design/parameters.md` lines 17–22 define `N`, limbs, and
`Q`; docs.rs `fhe_math::rq` describes polynomials over a product of prime moduli.

This domain matches fhe.rs BFV secret-key consumption directly.

Citation: docs.rs `fhe/bfv/keys/secret_key.rs` lines 20–25 and 211–218.

#### Round complexity

The natural PVTHFHE ceremony remains three rounds: share distribution,
verification/complaint, and aggregation.

Citation: `.sisyphus/design/spec-keygen.md` lines 19–40.

If all proofs are Fiat-Shamir non-interactive, the happy path can be two network
phases plus final transcript publication.

Citation: `.sisyphus/design/spec-real-p2p3.md` lines 93–112 describe the existing
Fiat-Shamir/Cyclo direction for RLWE statements.

#### Per-party computation cost

Per party cost is `O(n*N*L)` for share generation/aggregation plus NTT-backed
BFV public-key-share operations.

Citation: `.sisyphus/design/parameters.md` lines 17–22 fix `N=8192`, `L=3`, and
the moduli.

Each verifier may also verify up to `n` dealer RLWE proofs.

Citation: `.sisyphus/design/spec-pvss.md` lines 22–28 define per-recipient proof
obligations.

#### Per-party communication cost

The private-share floor is one BFV-sized share per recipient.

At canonical parameters the limb-aligned share size is 196,608 bytes before proof
and commitment overhead.

Citation: `.sisyphus/design/parameters.md` lines 27–36.

Broadcast material includes a public-key share, commitment data, and proof bytes.

Citation: `.sisyphus/design/spec-real-p2p3.md` lines 214–220 show existing RLWE
proof-size estimates are large even at illustrative smaller degree.

#### Ceremony assumptions

The ceremony needs authenticated participants, encrypted private channels,
bulletin-board broadcast, common random polynomial derivation, Fiat-Shamir domain
separation, and likely Ajtai/Cyclo commitment parameters.

Citation: `.sisyphus/design/spec-keygen.md` lines 17–18 and
`.sisyphus/design/assumptions-ledger.md` lines 87–96.

#### Public-verifiability story

Public verifiability proves the correct object: a BFV public-key-share relation
over a short secret and bounded noise.

Citation: `.sisyphus/design/spec-pvss.md` lines 22–29.

The downside is cost: direct RLWE verification in Noir is expensive.

Citation: `.sisyphus/design/assumptions-ledger.md` lines 135–143 mark the final
circuit size as conditional.

The intended mitigation is to bind folded/off-chain lattice proof artefacts into
`dkg_root`, rather than scalarizing the key algebra.

Citation: `.sisyphus/design/spec-real-p2p3.md` lines 50–64 bind only hashes and
roots on-chain.

#### Implementation evidence

Discrete-log Pedersen/Feldman DKG libraries exist, but no drop-in
fhe.rs-compatible RLWE DKG was found.

Evidence: `mikelodder7/vsss-rs`, `docknetwork/crypto` commit
`1929e47ad4d004c3bb99a14d0ce6223deb03c9e9`, and `project-dkg/dkg` implement
scalar/group VSS/DKG families.

Citation: GitHub search results for Pedersen/Feldman DKG; local fhe.rs pin at
`crates/pvthfhe-fhe/Cargo.toml` lines 25–27.

### Candidate 2 — Shamir over BN254 scalar with Feldman VSS

#### Protocol sketch

Each dealer treats the secret as one or more BN254 scalar values, shares those
values with Shamir polynomials, and broadcasts Feldman coefficient commitments.

Citation: Shamir 1979 DOI 10.1145/359168.359176; Feldman FOCS 1987 DOI
10.1109/SFCS.1987.4.

Each receiver verifies its scalar share against the public commitments.

Citation: Gennaro et al. EUROCRYPT 1999 references Feldman and Shamir in the
Springer reference list.

For PVTHFHE, this must be repeated for BFV coefficients or RNS residues unless a
seed-to-key bridge is introduced.

Citation: docs.rs `SecretKey` source lines 20–25; `.sisyphus/design/parameters.md`
lines 17–25.

#### Paper citation

Primary papers are Shamir 1979, Feldman 1987, and Gennaro-Jarecki-Krawczyk-Rabin
1999.

Citation: Springer Gennaro et al. page lists DOI 10.1007/3-540-48910-X_21.

#### Secret-sharing field

Native domain is BN254 scalar field `Fr`.

Citation: `.sisyphus/design/assumptions-ledger.md` lines 52–61 list BN254
discrete-log/pairing assumptions.

This is not the fhe.rs BFV secret-key domain.

Citation: docs.rs `fhe/bfv/keys/secret_key.rs` lines 20–25.

#### Round complexity

Feldman VSS can be one private-send round plus public commitments, with complaint
and finalization added for DKG robustness.

Citation: `.sisyphus/design/spec-keygen.md` lines 19–40.

Gennaro et al. show earlier DKGs can be biased by active attackers, so robust
DKG checks are mandatory.

Citation: Springer abstract for Gennaro et al. states active attackers can bias
generated keys and motivates their secure DKG.

#### Per-party computation cost

One scalar secret is cheap: `O(t)` field operations and group commitments.

For BFV coefficient-wise sharing, multiply by `8192` lanes.

For RNS-residue sharing, multiply by `8192*3 = 24576` lanes.

Citation: `.sisyphus/design/parameters.md` lines 17–22.

#### Per-party communication cost

One scalar secret requires `O(n)` scalar shares and `O(t)` group commitments.

Coefficient-wise BFV sharing requires thousands of such lanes and can exceed the
native BFV share size once commitments are included.

Citation: `.sisyphus/design/parameters.md` lines 34–35.

#### Ceremony assumptions

The ceremony needs private channels, broadcast commitments, fixed BN254 group
generators, and a scalar-to-BFV binding proof.

Citation: `.sisyphus/design/assumptions-ledger.md` lines 52–61 and 87–96.

Feldman is not post-quantum.

Citation: `.sisyphus/design/assumptions-ledger.md` lines 52–55.

#### Public-verifiability story

This is the most Noir-friendly option for scalar VSS.

Citation: BN254 is the arithmetic context of the P3/UltraHonk assumptions in
`.sisyphus/design/assumptions-ledger.md` lines 52–61.

But scalar VSS does not prove the BFV public-key-share relation unless a bridge
proof is added.

Citation: `.sisyphus/design/spec-pvss.md` lines 16–29 define BFV/RLWE sharing and
encryption relations, not BN254 scalar relations.

Without that bridge, it proves a DKG for the wrong object.

#### Implementation evidence

This option has the best commodity implementation support.

Evidence: `mikelodder7/vsss-rs`, `docknetwork/crypto`, `bytemare/secret-sharing`,
and `0xstepit/dkg-from-scratch` provide Shamir/Feldman/Pedersen-style scalar VSS
or DKG examples.

Citation: GitHub search results returned those repositories and descriptions.

### Candidate 3 — Lattice-based VSS / trapdoor-commitment family

#### Protocol sketch

This family commits to lattice/module secrets and proves consistency of shares,
openings, and shortness using lattice assumptions.

Citation: Damgård-Orlandi-Takahashi-Tibouchi, PKC 2021 / JoC 2022, DOI
10.1007/978-3-030-75245-3_5 and DOI 10.1007/s00145-022-09425-3.

DOT(T) provides lattice trapdoor commitments and round-efficient distributed
signatures, not a complete BFV DKG.

Citation: Springer abstract describes two-round n-out-of-n distributed signing,
multi-signatures, homomorphic commitments, and module-SIS/LWE assumptions.

#### Paper citation

Primary citation is Ivan Damgård, Claudio Orlandi, Akira Takahashi, Mehdi
Tibouchi, "Two-Round n-out-of-n and Multi-Signatures and Trapdoor Commitment
from Lattices," PKC 2021 / Journal of Cryptology 2022 / ePrint 2020/1110.

Citation: web search returned PKC DOI, JoC DOI, and ePrint 2020/1110.

#### Secret-sharing field

The native domain is module/RLWE lattice modules, closer to BFV than BN254.

Citation: `.sisyphus/design/assumptions-ledger.md` lines 40–49 list the existing
lattice assumptions.

Concrete parameters still need alignment with PVTHFHE's `R_q`.

Citation: `.sisyphus/design/parameters.md` lines 13–25.

#### Round complexity

DOT(T) signatures achieve two-round n-out-of-n signing, but a BFV DKG adaptation
would still need setup, share distribution, proof/complaint, and aggregation.

Citation: Springer abstract and `.sisyphus/design/spec-keygen.md` lines 19–40.

#### Per-party computation cost

Expected cost is at least `O(n*N*L)` share movement plus module-SIS/LWE
commitment and proof work.

Citation: `.sisyphus/design/parameters.md` lines 17–22.

Concrete constants are unknown until the PVTHFHE-specific VSS relation is
specified.

#### Per-party communication cost

The BFV private-share floor remains about 196 KB per recipient before lattice
commitments and openings.

Citation: `.sisyphus/design/parameters.md` lines 34–35.

DOT(T) communication estimates cannot be used directly because the paper targets
distributed signatures rather than BFV DKG.

Citation: Springer abstract for DOT(T).

#### Ceremony assumptions

This route needs lattice commitment parameters and may need trapdoor commitment
key generation or a proof that trapdoors are unavailable in the real ceremony.

Citation: DOT(T) snippets identify trapdoor commitments as central to the
two-round construction.

It also needs the ordinary DKG registry, channels, and broadcast transcript.

Citation: `.sisyphus/design/spec-keygen.md` lines 17–40.

#### Public-verifiability story

The algebraic story is clean because the proof can speak lattice/RLWE.

Citation: `.sisyphus/design/assumptions-ledger.md` lines 40–49.

The practical story is weak because no PVTHFHE-specific lattice VSS proof system
is already specified.

Citation: `.sisyphus/design/assumptions-ledger.md` lines 100–143 already list
conditional extractor and circuit-size risks for existing lattice proofs.

#### Implementation evidence

No production-ready fhe.rs-compatible lattice VSS implementation was found.

Search found DOT(T) papers and `uishi/LHSS`, but LHSS is lattice homomorphic
secret sharing for two-party computation, not BFV DKG.

Citation: GitHub/search results for lattice VSS and LHSS.

---

## Compatibility with `gnosisguild/fhe.rs` BFV

Upstream `fhe::bfv::SecretKey` stores BFV secret material as `coeffs:
Box<[i64]>` under `BfvParameters`.

Citation: docs.rs `fhe/bfv/keys/secret_key.rs` lines 20–25.

`SecretKey::random` samples coefficient vectors using the parameter degree.

Citation: docs.rs `fhe/bfv/keys/secret_key.rs` lines 42–45.

Decryption converts coefficients into `fhe_math::rq::Poly` in a ciphertext
context.

Citation: docs.rs `fhe/bfv/keys/secret_key.rs` lines 211–218.

Local PVTHFHE stores `sk.coeffs.to_vec()` after fhe.rs key generation.

Citation: `crates/pvthfhe-fhe/src/fhers.rs` lines 429–452.

Local PVTHFHE also stores and consumes full `Poly` values for threshold shares.

Citation: `crates/pvthfhe-fhe/src/fhers.rs` lines 31–40 and 186–215.

The fhe.rs dependency is pinned to `gnosisguild/fhe.rs` rev
`5f24d0b62a7329b789db07a065b68accd614a47b`.

Citation: `crates/pvthfhe-fhe/Cargo.toml` lines 25–27.

Candidate 1 matches this representation natively.

Candidate 3 matches the lattice family but lacks a concrete PVTHFHE DKG.

Candidate 2 matches Noir but not the BFV secret representation.

Candidate 2 therefore needs one of three bridges:

- coefficient-wise sharing over 8192 scalar lanes;
- RNS-residue sharing over 24576 scalar lanes;
- seed sharing with a proof of deterministic expansion into BFV coefficients.

Citation: `.sisyphus/design/parameters.md` lines 17–22 and 31–35.

The seed option is especially risky because R0 hardened against seeded RNG in
production paths.

Citation: `.sisyphus/notepads/pvthfhe-remediation/learnings.md` lines 107–120.

Conclusion: the DKG algebra should stay in the BFV ring domain and only export
hashes/proof commitments to the BN254/Noir/on-chain layer.

---

## Comparison Matrix

| Candidate | cost/party | rounds | ceremony | fhe.rs-compat | public-verifiability | soundness assumption | ZK-friendly for Noir circuits |
|---|---|---:|---|---|---|---|---|
| Pedersen-DKG over RLWE / threshold FHE | `O(n*N*L)` share/proof work plus BFV NTT work; ≈196 KB private-share floor | 3 in current spec; 2+finalize possible on happy path | PKI/private channels, broadcast transcript, common random polynomial, FS domains, likely Ajtai/Cyclo CRS | **Strong**: shares coefficient vectors / `R_q` polynomials consumed by fhe.rs | Verifies the right BFV public-key-share object; expensive | RLWE/LWE plus M-SIS/Ajtai/Cyclo assumptions; existing conditional P1 caveats | Medium/low; best via folded lattice proof and root binding |
| Shamir over BN254 scalar + Feldman VSS | Cheap for one scalar; costly for 8192 or 24576 BFV lanes | 2–3 with complaint/finalize | Private channels, broadcast commitments, BN254 generators, BFV bridge | **Weak** without coefficient/RNS bridge | Excellent for scalar DKG, incomplete for BFV key correctness | Discrete log / pairing; non-PQ; Gennaro anti-bias checks | High for scalar arithmetic and commitments |
| Lattice VSS / DOT(T)-style commitments | Unknown constants; at least `O(n*N*L)` plus lattice commitments | DOT(T) signatures are 2-round; BFV DKG likely 3+ | Lattice commitment params, possible trapdoor setup, private channels, broadcast | Medium/strong algebraically, but no concrete fhe.rs DKG | Theoretically aligned if a PVTHFHE VSS relation is designed | Module-SIS/LWE plus trapdoor-commitment assumptions; new extractor obligations | Low/medium; requires folding/wrapping |

Matrix citations: `.sisyphus/design/parameters.md` lines 17–35;
`.sisyphus/design/spec-keygen.md` lines 19–40; docs.rs SecretKey lines 20–25;
`.sisyphus/design/assumptions-ledger.md` lines 52–61 and 100–143.

---

## Recommendation

**Recommended pending oracle review: Candidate 1 — Pedersen-DKG over the
BFV/RLWE secret domain, with public verifiability via an RLWE relation proof and
transcript commitment.**

Primary rationale: it shares the same object that fhe.rs decrypts with.

Citation: docs.rs `fhe/bfv/keys/secret_key.rs` lines 20–25 and 211–218.

Candidate 2 is simpler for Noir but proves scalar sharing unless it carries a
large BFV bridge.

Citation: `.sisyphus/design/spec-pvss.md` lines 16–29 define BFV/RLWE—not scalar
BN254—relations.

Candidate 3 is theoretically attractive but currently under-specified for a BFV
DKG implementation path.

Citation: DOT(T) paper pages describe distributed signatures and trapdoor
commitments, not a full BFV DKG.

R1.1 implication: reshare must be BFV-ring/coefficient-vector resharing with
fresh CSPRNG randomness, not deterministic party-id seeding.

Citation: `crates/pvthfhe-fhe/src/fhers.rs` lines 258–339; R0 RNG evidence in
notepad lines 107–120.

R1.2 implication: Shamir-or-equivalent should operate over the BFV secret
representation or CRT limbs, not GF(256) and not one BN254 scalar.

Citation: docs.rs SecretKey lines 20–25; `.sisyphus/design/parameters.md` lines
17–25.

R1.3 implication: encrypted-share randomness belongs in the PVSS witness and
must come from fresh CSPRNG output.

Citation: `.sisyphus/design/spec-pvss.md` lines 19–29.

R1.4 implication: smudging error should live in the same `R_q` / `Poly` domain as
decryption shares.

Citation: `crates/pvthfhe-fhe/src/fhers.rs` lines 31–40 and 174–180.

R1.5 implication: the ceremony should specify registry, session id, common random
polynomial, bulletin-board transcript, complaints/blame, proof policy, and
`dkg_root` derivation.

Citation: `.sisyphus/design/spec-keygen.md` lines 19–58 and
`.sisyphus/design/spec-real-p2p3.md` lines 50–64.

Fallback: Candidate 2 should only be chosen if oracle approves an explicit
coefficient/RNS bridge proof as simpler than RLWE public verification.

Research track: Candidate 3 should remain future work until a concrete BFV DKG
VSS relation and implementation evidence exist.

---

## Open Questions / Risks

1. The plan cites Asharov–Jain–Lopez-Alt–Tromer–Vaikuntanathan–Wichs, but ePrint
2011/613 metadata lists Asharov, Jain, and Wichs; oracle should confirm the
intended threshold-FHE lineage.

2. Candidate 1 verifies the right object, but direct RLWE verification may exceed
Noir/UltraHonk budgets; oracle should challenge the folded-proof/root-binding
approach.

3. fhe.rs samples CBD coefficients while the design parameter note says ternary;
oracle should choose the required DKG secret distribution.

4. R1.1 needs a decision on RNS-limb sharing versus aggregate-modulus ring
sharing.

5. Gennaro et al. warn about DKG bias; oracle should identify RLWE-specific
anti-bias checks for aggregate BFV keys.

6. If Ajtai/Cyclo commitments are reused, oracle should decide whether existing
CRS assumptions cover DKG or whether the assumptions ledger needs a new entry.

7. No production-ready fhe.rs-compatible RLWE DKG implementation was found;
oracle should decide whether this research risk is acceptable.

8. The on-chain verifier sees roots/hashes; oracle should define which DKG facts
must be proved inside Noir versus off-chain and committed under `dkg_root`.

---

## References

1. Gilad Asharov, Abhishek Jain, Daniel Wichs, "Multiparty Computation with Low
Communication, Computation and Interaction via Threshold FHE," IACR ePrint
2011/613, 2011/2012, https://eprint.iacr.org/2011/613.

2. Torben P. Pedersen, "A Threshold Cryptosystem without a Trusted Party,"
EUROCRYPT 1991, LNCS 547, pp. 522–526, DOI 10.1007/3-540-46416-6_47.

3. Torben P. Pedersen, "Non-Interactive and Information-Theoretic Secure
Verifiable Secret Sharing," CRYPTO 1991, LNCS 576, pp. 129–140, DOI
10.1007/3-540-46766-1_9.

4. Adi Shamir, "How to Share a Secret," Communications of the ACM 22(11):612–613,
1979, DOI 10.1145/359168.359176.

5. Paul Feldman, "A Practical Scheme for Non-interactive Verifiable Secret
Sharing," FOCS 1987, pp. 427–437, DOI 10.1109/SFCS.1987.4.

6. Rosario Gennaro, Stanisław Jarecki, Hugo Krawczyk, Tal Rabin, "Secure
Distributed Key Generation for Discrete-Log Based Cryptosystems," EUROCRYPT
1999, LNCS 1592, pp. 295–310, DOI 10.1007/3-540-48910-X_21.

7. Ivan Damgård, Claudio Orlandi, Akira Takahashi, Mehdi Tibouchi, "Two-Round
n-out-of-n and Multi-Signatures and Trapdoor Commitment from Lattices," PKC
2021, LNCS 12710, pp. 99–130, DOI 10.1007/978-3-030-75245-3_5.

8. Ivan Damgård, Claudio Orlandi, Akira Takahashi, Mehdi Tibouchi, "Two-Round
n-out-of-n and Multi-Signatures and Trapdoor Commitment from Lattices," Journal
of Cryptology 35, Article 14, 2022, DOI 10.1007/s00145-022-09425-3, ePrint
2020/1110.

9. Hermine lattice PVSS framework, cited in `.sisyphus/design/spec-pvss.md` line
36 as ePrint 2025/901.

10. trBFV / multiparty BFV context, cited in `.sisyphus/design/spec-pvss.md` line
37 as ePrint 2024/1285.

11. Local fhe.rs shim: `crates/pvthfhe-fhe/src/fhers.rs`, especially imports at
9–15, `PartyState` at 31–40, CRP at 74–80, decryption-share conversion at
157–215, sharing at 218–339, and keygen at 429–452.

12. Local dependency pin: `crates/pvthfhe-fhe/Cargo.toml` lines 25–27 pin
`gnosisguild/fhe.rs` rev `5f24d0b62a7329b789db07a065b68accd614a47b`.

13. Upstream fhe.rs `SecretKey`: docs.rs `fhe/bfv/keys/secret_key.rs` lines
20–25, 42–52, 145–156, and 211–218.

14. Upstream `fhe_math::rq`: docs.rs module documentation for CRT/RNS
polynomials and NTT/RNS modules.

15. Implementation-search breadcrumbs: `mikelodder7/vsss-rs`,
`docknetwork/crypto` commit `1929e47ad4d004c3bb99a14d0ce6223deb03c9e9`,
`bytemare/secret-sharing`, `project-dkg/dkg`, `0xstepit/dkg-from-scratch`, and
`uishi/LHSS`.

16. Abraham, Bacho, Stern — *Quadratic Asynchronous DKG from Plain Setup*
(ePrint 2026/1159). Introduces Key Escrow, Provable Rank, Weak Leader Election,
Non-Equivocation, Aggregatable PVSS, and Provable AVID primitives for ADKG.

---

## Candidate 4 — Paper 2026/1159 Building Blocks Augmenting Pedersen-DKG

### Protocol sketch

Rather than replacing the existing Pedersen-over-BFV DKG, this approach
augments it with five building blocks from the referenced paper:

- **Non-Equivocation** (§4.1): Bind each dealer to a single Round 1 message
  via Schnorr quorum signatures. Closes the equivocation blame gap in
  `spec-keygen.md`.

- **Provable AVID** (§4.3): Replace broadcast of all n encrypted shares with
  Merkle-root information dispersal. Each party retrieves only their assigned
  share with a Merkle inclusion proof.

- **Committee-Based Sharing** (§4.2 ref): Reduce DKG communication from
  O(n²) to O(λn) via committee selection. Dealers send to λ parties instead
  of all n.

- **Key Escrow** (§6): Generate ephemeral key pairs during DKG for decryption
  authorization. Secret key hidden until f+1 parties authorize reconstruction.

- **Weak Leader Election** (§7): Distributed aggregator selection with
  retroactive verifiability. Replaces single designated aggregator.

### Paper citation

ePrint 2026/1159, Abraham, Bacho, Stern — *Quadratic Asynchronous DKG from Plain Setup*.

Implemented as `crates/pvthfhe-non-equiv/`, `crates/pvthfhe-pvss/src/avid.rs`,
`crates/pvthfhe-pvss/src/key_escrow.rs`, `crates/pvthfhe-aggregator/src/leader_election.rs`.

### Round complexity

No additional rounds for AVID and committee sharing (modify existing Round 1).
One additional round (Round 1.5) for NonEquiv signatures.
Leader election runs after DKG before decryption.

### Per-party computation cost

NonEquiv: O(n) Schnorr sign + verify operations.
AVID: O(n) Merkle tree build + O(log n) proof verification per party.
Committee: O(λ) share encryptions per dealer instead of O(n).

### Ceremony assumptions

Schnorr signatures (BN254, existing), SHA-256 hashing, Merkle tree
commitments. No new cryptographic assumptions beyond what pvthfhe
already assumes in `assumptions-ledger.md`.

### Public-verifiability story

NonEquiv proofs and Merkle roots are publicly verifiable.
Leader election ranks are deterministically reproducible.
Key escrow commitments bind epoch and session.

### Integration plan

See `.sisyphus/plans/dkg-paper-integration.md` for full implementation plan.
