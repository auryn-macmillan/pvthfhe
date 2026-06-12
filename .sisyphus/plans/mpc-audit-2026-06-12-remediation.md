# MPC Audit Remediation Plan — 2026-06-12

**Source**: [`.sisyphus/audit/MPC-AUDIT-2026-06-12.md`](../audit/MPC-AUDIT-2026-06-12.md)
**Scope**: 13 findings (3 HIGH, 4 MEDIUM, 5 LOW, 1 INFO) across 8 crates
**Methodology**: TDD — write RED tests first, then implement, verify GREEN
**Threat model**: Malicious PPT adversary, static corruption ≤ t−1 of n, synchronous authenticated channels, ROM, honest majority, abort-with-public-blame, only verifier trusted
**Review**: Pending Momus (plan critic)

---

## Summary

| # | Severity | Component | Fix | Effort |
|---|----------|-----------|-----|--------|
| F1 | **HIGH** | `pvthfhe-non-equiv`, `pvthfhe-nizk/schnorr.rs` | Add `session_id` to Schnorr signatures + PoP | Medium |
| F2 | **HIGH** | `pvthfhe-pvss/avid.rs` | Add `session_id` to AVID Merkle `leaf_hash` | Small |
| F3 | **HIGH** | `pvthfhe-aggregator/leader_election.rs` | Add `session_id` to `generate_rank` | Small |
| F4 | **MEDIUM** | `pvthfhe-cyclo/fiat_shamir.rs` | Add label+length prefix to `CycloTernaryTranscript::absorb` | Small |
| F5 | **MEDIUM** | `pvthfhe-nizk/lib.rs`, `pvthfhe-pvss/lib.rs`, `pvthfhe-aggregator/folding/mod.rs` | Add `party_id` to error variants | Medium |
| F6 | **MEDIUM** | `pvthfhe-pvss/nizk_share.rs` | Replace `.expect()` with `Result` returns | Small |
| F7 | **MEDIUM** | `pvthfhe-keygen/dkg.rs`, `pvthfhe-aggregator/keygen/simulator.rs` | Add per-round timeout parameters | Medium |
| F8 | **LOW** | `pvthfhe-keygen/dkg.rs` | Add `party_id` to `DkgError` variants | Small |
| F9 | **LOW** | `pvthfhe-non-equiv/lib.rs` | Validate curve membership at deserialization | Small |
| F10 | **LOW** | `pvthfhe-pvss/nizk_keygen.rs` | Return `Result` on truncation instead of `vec![]` | Small |
| F11 | **LOW** | `pvthfhe-fhe/fhers.rs` | Add explicit `abort_session()` state-reset API | Small |
| F12 | **INFO** | Protocol-level | Document limitation; no code change | Zero |
| F13 | **INFO** | `pvthfhe-fhe/wire.rs` | Document limitation; no code change | Zero |

---

## Dependency Order

```
Workstream A (P0): F1 → F2 → F3   (session binding — independent of each other, can parallelize)
Workstream B (P1): F4              (transcript collision — independent of A)
Workstream C (P2): F5 → F6 → F8    (error types → expect removal → DkgError; progressive refinement)
Workstream D (P2): F7              (round timeouts — depends on F5 for BlameProof errors)
Workstream E (P3): F9, F10, F11    (hardening — fully independent)
Workstream F (doc): F12, F13       (documentation only)
```

**Critical path**: A → D (session binding enables correct BlameProof generation during timeout aborts)

---

## WORKSTREAM A: SESSION BINDING (F1, F2, F3) — P0 IMMEDIATE

All three HIGH findings share the same vulnerability class: domain-separated hashes that bind `(party_id, payload)` but exclude `session_id`, enabling cross-session replay. The fixes follow a uniform pattern: add `session_id: &[u8]` to the hashing function, update call sites, add domain tags if absent, write RED tests.

### F1: NonEquiv Schnorr Signatures + PoP Lack Session Binding

**Severity**: HIGH
**Files**:
- `crates/pvthfhe-non-equiv/src/lib.rs` — `hash_round1_message`, `non_equiv_challenge`
- `crates/pvthfhe-nizk/src/schnorr.rs` — `hash_to_challenge`, `pop_challenge`
- `crates/pvthfhe-aggregator/src/keygen/simulator.rs` — call sites at lines 334, 633

**Root cause**: The signature-hash chain `hash_round1_message → non_equiv_challenge → schnorr_sign(hash_to_challenge)` never incorporates `session_id`. Same for `pop_challenge`.

**Design decision for PoP**: PoP is used for long-term key registration. Per the audit, if keys are reused across sessions, session-independent PoP is acceptable. If keys become session-scoped in future, PoP must bind session. The plan: **document the design assumption** at the `pop_challenge` callsite and in SECURITY.md, but do NOT add session_id to PoP at this time (to avoid breaking the "long-term key" model). Add a `// DESIGN: PoP is intentionally session-independent for long-term keys` comment.

#### Concrete Code Changes

**Step 1 — TDD: Write RED tests**

File: `crates/pvthfhe-non-equiv/src/lib.rs` (test module, ~line 594)

Add:
```rust
#[test]
fn test_message_hash_binds_session_id() {
    let h1 = hash_round1_message(1, b"payload", b"session-alpha");
    let h2 = hash_round1_message(1, b"payload", b"session-beta");
    assert_ne!(h1, h2, "different session must produce different hash");
}

#[test]
fn test_message_hash_same_session_deterministic() {
    let h1 = hash_round1_message(1, b"payload", b"session-alpha");
    let h2 = hash_round1_message(1, b"payload", b"session-alpha");
    assert_eq!(h1, h2, "same session must be deterministic");
}

#[test]
fn test_nonequiv_signature_cross_session_replay_rejected() {
    // Sign message in session A, verify fails in session B
    let mut rng = make_rng();
    let (sk, pk) = generate_signing_keypair(&mut rng);
    let msg_hash_a = hash_round1_message(1, b"round1 data", b"session-A");
    let msg_hash_b = hash_round1_message(1, b"round1 data", b"session-B");

    // Signature computed for session-A hash
    let sig = produce_signed_signature(7, sk, pk, 1, &msg_hash_a, &mut rng);

    // Should verify against session-A
    assert!(verify_signature(&sig, &pk, &msg_hash_a).is_ok());

    // Should REJECT when verified against session-B message hash
    assert!(verify_signature(&sig, &pk, &msg_hash_b).is_err(),
        "cross-session signature replay must be rejected");
}
```

File: `crates/pvthfhe-nizk/src/schnorr.rs` (test module, ~line 154)

Add:
```rust
#[test]
fn schnorr_challenge_binds_session() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
    let (sk, pk) = generate_signing_keypair(&mut rng);
    let msg = Fr::from(42u64);
    let (r_a, s_a) = schnorr_sign_with_session(sk, msg, b"session-A", &mut rng);
    let (r_b, s_b) = schnorr_sign_with_session(sk, msg, b"session-B", &mut rng);
    // Signatures over same message but different sessions must differ
    assert!(r_a != r_b || s_a != s_b,
        "signatures across sessions must diverge (different challenge)");
    // Session-A sig must verify with session-A context
    assert!(schnorr_verify_with_session(pk, r_a, s_a, msg, b"session-A"));
    // Session-A sig must REJECT with session-B context
    assert!(!schnorr_verify_with_session(pk, r_a, s_a, msg, b"session-B"));
}
```

**Step 2 — GREEN: Implement fixes**

File: `crates/pvthfhe-non-equiv/src/lib.rs`

Modify `hash_round1_message` (line 124):
```rust
/// Hash a dealer's Round 1 message for NonEquiv signing.
///
/// Domain-separated SHA-256 over `(session_id, dealer_id, round1_payload)`.
pub fn hash_round1_message(dealer_id: u32, round1_payload: &[u8], session_id: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_SEPARATOR);
    h.update(b":msg-hash:");
    h.update(session_id);                       // ← NEW: bind session
    h.update(&dealer_id.to_be_bytes());
    h.update(round1_payload);
    h.finalize().into()
}
```

Modify `non_equiv_challenge` (line 138):
```rust
pub fn non_equiv_challenge(message_hash: &[u8; 32], session_id: &[u8]) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SEPARATOR);
    hasher.update(b":challenge:");
    hasher.update(session_id);                  // ← NEW: bind session
    hasher.update(message_hash);
    let digest: [u8; 32] = hasher.finalize().into();
    Fr::from_le_bytes_mod_order(&digest)
}
```

Modify `produce_signature` (line 157) — add `session_id` parameter, thread to both `non_equiv_challenge` and `schnorr_sign`:
```rust
pub fn produce_signature(
    signer_sk: Fr,
    _signer_pk: G1Affine,
    _dealer_id: u32,
    message_hash: &[u8; 32],
    session_id: &[u8],
    rng: &mut impl RngCore,
) -> NonEquivSignature {
    let msg_fr = non_equiv_challenge(message_hash, session_id);
    let (sig_r, sig_s) = schnorr_sign_with_session(signer_sk, msg_fr, session_id, rng);
    NonEquivSignature {
        signer_id: 0,
        sig_r,
        sig_s,
    }
}
```

Modify `produce_signed_signature` (line 174) — add `session_id`:
```rust
pub fn produce_signed_signature(
    signer_id: u32,
    signer_sk: Fr,
    signer_pk: G1Affine,
    dealer_id: u32,
    message_hash: &[u8; 32],
    session_id: &[u8],
    rng: &mut impl RngCore,
) -> NonEquivSignature {
    let mut sig = produce_signature(signer_sk, signer_pk, dealer_id, message_hash, session_id, rng);
    sig.signer_id = signer_id;
    sig
}
```

Modify `verify_signature` (line 247) — add `session_id`:
```rust
pub fn verify_signature(
    sig: &NonEquivSignature,
    signer_pk: &G1Affine,
    message_hash: &[u8; 32],
    session_id: &[u8],
) -> Result<(), NonEquivError> {
    let challenge = non_equiv_challenge(message_hash, session_id);
    if !schnorr_verify_with_session(*signer_pk, sig.sig_r, sig.sig_s, challenge, session_id) {
        return Err(NonEquivError::InvalidSignature(sig.signer_id));
    }
    Ok(())
}
```

Modify `verify_nonequiv_proof` (line 265) — add `session_id` and thread to `verify_signature`:
```rust
pub fn verify_nonequiv_proof(
    proof: &NonEquivProof,
    public_keys: &HashMap<u32, G1Affine>,
    message_hash: &[u8; 32],
    session_id: &[u8],
) -> Result<(), NonEquivError> {
    // ... existing checks ...
    for sig in &proof.signatures {
        // ...
        verify_signature(sig, pk, &proof.message_hash, session_id)?;
    }
    // ...
}
```

File: `crates/pvthfhe-nizk/src/schnorr.rs`

Modify `hash_to_challenge` (line 108) — add `session_id`:
```rust
fn hash_to_challenge(r: &G1Affine, pk: &G1Affine, message: Fr, session_id: &[u8]) -> Fr {
    let mut h = Sha256::new();
    h.update(pvthfhe_domain_tags::Tag::SchnorrChallenge.as_bytes());
    h.update(session_id);                       // ← NEW: bind session
    h.update(affine_to_bytes(r, true));
    h.update(affine_to_bytes(r, false));
    h.update(affine_to_bytes(pk, true));
    h.update(affine_to_bytes(pk, false));
    let msg_bytes = message.into_bigint().to_bytes_le();
    h.update(&msg_bytes);
    Fr::from_be_bytes_mod_order(&h.finalize())
}
```

Add `schnorr_sign_with_session` and `schnorr_verify_with_session` (session-aware wrappers):
```rust
/// Sign with session binding (for NonEquiv protocol).
pub fn schnorr_sign_with_session(
    sk: Fr, message: Fr, session_id: &[u8], rng: &mut impl RngCore,
) -> (G1Affine, Fr) {
    let mut buf = [0u8; 64];
    rng.fill_bytes(&mut buf);
    let r = Fr::from_le_bytes_mod_order(&buf);
    let r_point = (G1Projective::generator() * r).into_affine();
    let pk_point = (G1Projective::generator() * sk).into_affine();
    let challenge = hash_to_challenge(&r_point, &pk_point, message, session_id);
    let s = r + challenge * sk;
    (r_point, s)
}

/// Verify with session binding (for NonEquiv protocol).
pub fn schnorr_verify_with_session(
    pk: G1Affine, sig_r: G1Affine, sig_s: Fr, message: Fr, session_id: &[u8],
) -> bool {
    if !pk.is_on_curve() || !sig_r.is_on_curve() { return false; }
    let challenge = hash_to_challenge(&sig_r, &pk, message, session_id);
    let left = G1Projective::generator() * sig_s;
    let right = sig_r.into_group() + pk.into_group() * challenge;
    left.into_affine() == right.into_affine()
}
```

**Keep** the existing `schnorr_sign` and `schnorr_verify` (session-independent) as-is for backward compatibility (e.g., `schnorr_pop_prove` uses the session-independent path).

Add DESIGN comment at `pop_challenge` (line 69):
```rust
/// DESIGN: PoP is intentionally session-independent.
/// Keys are long-term (reused across DKG sessions). Session binding is not
/// required for PoP since the proof demonstrates knowledge of sk for a given
/// pk — replaying the same PoP in a different session does not grant new
/// capabilities. If keys become session-scoped, add `session_id` here.
fn pop_challenge(pk: G1Affine) -> Fr {
```

**Step 3 — Update call sites**

File: `crates/pvthfhe-aggregator/src/keygen/simulator.rs`

Line 334: `hash_round1_message(dealer_id, &payload)` → `hash_round1_message(dealer_id, &payload, &session_id)`
Line 633: `hash_round1_message(dealer_id, &payload)` → `hash_round1_message(dealer_id, &payload, &session_id)`
Line 346: `NonEquivCollector::new(dealer_id, msg_hash, self.n_parties, f)` — unchanged (collector doesn't need session_id; the hash already binds it)
Line 634-641: `produce_signed_signature(signer_id, signing_key, signing_pk, dealer_id, &msg_hash, &mut rng)` → add `&session_id` parameter
Line ~360+: `verify_nonequiv_proof(&proof, &pks, &msg_hash)` → add `&session_id`

**Step 4 — Update tests in non-equiv/lib.rs**

All existing tests calling `hash_round1_message` need a `session_id` argument. Use `b"test-session"` as a constant:
```rust
const TEST_SESSION: &[u8] = b"test-session";
```
Update all 14 call sites in the test module.

**Step 5 — Verify**

```bash
cargo test -p pvthfhe-non-equiv
cargo test -p pvthfhe-nizk -- schnorr
cargo test -p pvthfhe-aggregator -- keygen
```

---

### F2: AVID Merkle Tree Lacks Session Binding

**Severity**: HIGH
**Files**:
- `crates/pvthfhe-pvss/src/avid.rs` — `leaf_hash`, `disperse`, `verify_retrieval`

**Root cause**: `leaf_hash` binds `(party_id, share_bytes)` but not `session_id`.

#### Concrete Code Changes

**Step 1 — TDD: Write RED test**

File: `crates/pvthfhe-pvss/src/avid.rs` (test module, ~line 389)

Add:
```rust
#[test]
fn test_avid_leaf_hash_binds_session() {
    let h1 = leaf_hash(1, b"share-data", b"session-A");
    let h2 = leaf_hash(1, b"share-data", b"session-B");
    assert_ne!(h1, h2, "different session must produce different leaf hash");
}

#[test]
fn test_avid_leaf_hash_same_session_deterministic() {
    let h1 = leaf_hash(1, b"share-data", b"session-C");
    let h2 = leaf_hash(1, b"share-data", b"session-C");
    assert_eq!(h1, h2, "same session must be deterministic");
}

#[test]
fn test_avid_cross_session_share_replay_rejected() {
    let mut shares_a = HashMap::new();
    let mut shares_b = HashMap::new();
    for i in 0..5u32 {
        shares_a.insert(i + 1, vec![i as u8; 32]);
        shares_b.insert(i + 1, vec![i as u8; 32]);
    }
    let dispersed_a = disperse(&shares_a, b"session-A");
    let dispersed_b = disperse(&shares_b, b"session-B");

    // Merkle roots must differ across sessions even with identical shares
    assert_ne!(dispersed_a.merkle_root, dispersed_b.merkle_root,
        "different session must produce different Merkle root");

    // Session-A proof must NOT verify against session-B root
    let proof = dispersed_a.proofs.get(&1).unwrap();
    let share = shares_a.get(&1).unwrap();
    assert!(!verify_retrieval(&dispersed_b.merkle_root, 1, share, proof, b"session-B"),
        "cross-session Merkle proof must be rejected");
}
```

**Step 2 — GREEN: Implement fix**

Modify `leaf_hash` (line 55):
```rust
fn leaf_hash(party_id: u32, share_bytes: &[u8], session_id: &[u8]) -> Fr {
    let mut h = Sha256::new();
    h.update(DOMAIN_SEPARATOR);
    h.update(b":leaf:");
    h.update(session_id);                       // ← NEW: bind session
    h.update(&party_id.to_be_bytes());
    h.update(share_bytes);
    Fr::from_be_bytes_mod_order(&h.finalize())
}
```

Modify `disperse` (line 122) — add `session_id` parameter:
```rust
pub fn disperse(shares: &HashMap<u32, Vec<u8>>, session_id: &[u8]) -> DispersedShares {
    // ...
    let leaves: Vec<Fr> = sorted
        .iter()
        .map(|(id, bytes)| leaf_hash(*id, bytes, session_id))
        .collect();
    // ...
}
```

Modify `verify_retrieval` (line 149) — add `session_id` parameter:
```rust
pub fn verify_retrieval(
    merkle_root: &Fr,
    party_id: u32,
    share_bytes: &[u8],
    proof: &MerkleInclusionProof,
    session_id: &[u8],
) -> bool {
    let leaf = leaf_hash(party_id, share_bytes, session_id);
    // ... rest unchanged ...
}
```

**Step 3 — Update call sites**

The `avid` module is not yet called from any other crate (only its own tests). All existing test calls need `session_id` added:
- `disperse(&shares)` → `disperse(&shares, b"test-session")`
- `verify_retrieval(&root, id, share, proof)` → `verify_retrieval(&root, id, share, proof, b"test-session")`

**Step 4 — Verify**

```bash
cargo test -p pvthfhe-pvss -- avid
```

---

### F3: Leader Election Lacks Session Binding

**Severity**: HIGH
**Files**:
- `crates/pvthfhe-aggregator/src/leader_election.rs` — `generate_rank`
- Caller: `elect_leader`, `deterministic_leader`, `rank_verify` (all in same file)

**Root cause**: `generate_rank` binds `(seed, party_id)` but not `session_id`.

#### Concrete Code Changes

**Step 1 — TDD: Write RED test**

File: `crates/pvthfhe-aggregator/src/leader_election.rs` (test module, ~line 140)

Add:
```rust
#[test]
fn test_rank_binds_session() {
    let seed = [0x42; 32];
    let r1 = generate_rank(&seed, 7, b"session-A");
    let r2 = generate_rank(&seed, 7, b"session-B");
    assert_ne!(r1.rank, r2.rank, "different session must produce different rank");
}

#[test]
fn test_cross_session_rank_replay_rejected() {
    let seed = [0x42; 32];
    let rank_a = generate_rank(&seed, 5, b"session-A");
    let rank_b = generate_rank(&seed, 5, b"session-B");
    assert!(!rank_verify(&rank_a, b"session-B"),
        "rank from session A must not verify in session B");
}

#[test]
fn test_elect_leader_session_binding() {
    let seed = [0x42; 32];
    let ids: Vec<u32> = (1..=5).collect();
    let r1 = elect_leader(&seed, &ids, b"session-A");
    let r2 = elect_leader(&seed, &ids, b"session-B");
    // Leaders may differ across sessions
    // At minimum, leader is in participant set
    assert!(ids.contains(&r1.leader_id));
    assert!(ids.contains(&r2.leader_id));
}
```

**Step 2 — GREEN: Implement fix**

Modify `generate_rank` (line 34):
```rust
pub fn generate_rank(seed: &[u8; 32], party_id: u32, session_id: &[u8]) -> ProvableRank {
    let mut h = Sha256::new();
    h.update(DOMAIN_SEPARATOR);
    h.update(b":rank:");
    h.update(session_id);                       // ← NEW: bind session
    h.update(seed);
    h.update(&party_id.to_be_bytes());
    let rank: [u8; 32] = h.finalize().into();
    ProvableRank {
        party_id,
        rank,
        proof: LeaderElectionProof {
            seed: *seed,
            party_id,
        },
    }
}
```

Modify `rank_verify` (line 52):
```rust
pub fn rank_verify(rank: &ProvableRank, session_id: &[u8]) -> bool {
    let expected = generate_rank(&rank.proof.seed, rank.proof.party_id, session_id);
    expected.rank == rank.rank
}
```

Modify `elect_leader` (line 59):
```rust
pub fn elect_leader(seed: &[u8; 32], participant_ids: &[u32], session_id: &[u8]) -> ElectionResult {
    let mut rankings: Vec<ProvableRank> = participant_ids
        .iter()
        .map(|&id| generate_rank(seed, id, session_id))
        .collect();
    // ...
}
```

Modify `deterministic_leader` (line 74):
```rust
pub fn deterministic_leader(seed: &[u8; 32], participant_ids: &[u32], session_id: &[u8]) -> u32 {
    let result = elect_leader(seed, participant_ids, session_id);
    result.leader_id
}
```

**Step 3 — Update call sites**

All calls are within `leader_election.rs` itself (tests and public API). Update all 9 call sites in test module to pass `b"test-session"`.

If `generate_rank` or `elect_leader` is called from other crates, add `session_id` at those call sites. Check with:
```bash
grep -rn "generate_rank\|elect_leader\|deterministic_leader\|rank_verify" crates/ --include="*.rs" | grep -v "leader_election.rs"
```
(Currently, no external callers found — leader election is not yet wired into the simulator.)

**Step 4 — Verify**

```bash
cargo test -p pvthfhe-aggregator -- leader_election
```

---

## WORKSTREAM B: TRANSCRIPT COLLISION (F4) — P1 HIGH

### F4: CycloTernaryTranscript::absorb Has No Label/Length Prefix

**Severity**: MEDIUM
**Files**:
- `crates/pvthfhe-cyclo/src/fiat_shamir.rs` — `CycloTernaryTranscript::absorb`
- `crates/pvthfhe-cyclo/tests/cyclo_ternary_transcript.rs` — test updates

**Root cause**: `absorb` writes raw bytes without label or length prefix, enabling absorb-collision attacks when an adversary controls data chunking.

**Reference implementation**: `pvthfhe-nizk/src/fiat_shamir.rs` `Transcript::absorb` (line 68) uses `u64_be(label.len()) ‖ label ‖ u64_be(data.len()) ‖ data`.

#### Concrete Code Changes

**Step 1 — TDD: Write RED test**

File: `crates/pvthfhe-cyclo/tests/cyclo_ternary_transcript.rs` (append)

```rust
#[test]
fn absorb_label_binding_prevents_chunking_ambiguity() {
    // Without label+length prefix, absorb(b"AB") + absorb(b"CD")
    // produces the same state as absorb(b"ABCD"). This test MUST fail
    // before the fix and pass after.
    let mut t1 = CycloTernaryTranscript::new("det-test", 0);
    t1.absorb(b"label-a", b"ABCD");

    let mut t2 = CycloTernaryTranscript::new("det-test", 0);
    t2.absorb(b"label-a", b"AB");
    t2.absorb(b"label-b", b"CD");

    // After fix: different labels → different state → different challenges
    let c1 = t1.sample_challenge();
    let c2 = t2.sample_challenge();
    assert_ne!(c1, c2, "chunking with different labels must produce different challenges");
}

#[test]
fn absorb_with_same_label_produces_deterministic_output() {
    let mut t1 = CycloTernaryTranscript::new("det-test", 0);
    t1.absorb(b"label-a", b"ABCD");

    let mut t2 = CycloTernaryTranscript::new("det-test", 0);
    t2.absorb(b"label-a", b"ABCD");

    assert_eq!(t1.sample_challenge(), t2.sample_challenge(),
        "same absorb sequence must be deterministic");
}
```

**Step 2 — GREEN: Implement fix**

Modify `CycloTernaryTranscript::absorb` (line 122):
```rust
/// Absorb labeled data into the transcript with length-prefixed encoding.
///
/// Wire format: `u64_be(label.len()) ‖ label ‖ u64_be(data.len()) ‖ data`.
/// Length prefixes prevent chunking ambiguity: `absorb("A", "BC")` followed
/// by `absorb("D", "EF")` produces a different state than `absorb("AD", "BCEF")`.
pub fn absorb(&mut self, label: &[u8], data: &[u8]) {
    self.state.update(
        u64::try_from(label.len()).map_or(u64::MAX, |v| v).to_be_bytes(),
    );
    self.state.update(label);
    self.state.update(
        u64::try_from(data.len()).map_or(u64::MAX, |v| v).to_be_bytes(),
    );
    self.state.update(data);
}
```

**Step 3 — Update all call sites**

File: `crates/pvthfhe-cyclo/tests/cyclo_ternary_transcript.rs`

All `.absorb(data)` calls become `.absorb(label, data)`:
- Line 25: `t2.absorb(b"fold-data")` → `t2.absorb(b"fold", b"fold-data")`
- Line 57: `transcript.absorb(&i.to_le_bytes())` → `transcript.absorb(b"counter", &i.to_le_bytes())`
- Line 91: `t1.absorb(b"aaa")` → `t1.absorb(b"input", b"aaa")`
- Line 94: `t2.absorb(b"bbb")` → `t2.absorb(b"input", b"bbb")`
- Line 100: `t1b.absorb(b"aaa")` → `t1b.absorb(b"input", b"aaa")`
- Line 102: `t2b.absorb(b"bbb")` → `t2b.absorb(b"input", b"bbb")`

If `CycloTernaryTranscript` is used outside tests, grep and update:
```bash
grep -rn "\.absorb(" crates/pvthfhe-cyclo/ --include="*.rs"
```
(Currently no production call sites — the transcript is only used in tests.)

**Step 4 — Verify**

```bash
cargo test -p pvthfhe-cyclo
```

---

## WORKSTREAM C: ERROR TYPE HARDENING (F5, F6, F8) — P2 MEDIUM

All three error-type findings share the theme: errors lack `party_id` context, preventing the verifier from issuing `BlameProof`. Fix them in dependency order: F5 (error type enrichment) → F6 (expect removal) → F8 (DkgError parallel).

### F5: NIZK Errors Are Opaque (No Party ID)

**Severity**: MEDIUM
**Files**:
- `crates/pvthfhe-nizk/src/lib.rs` — `NizkError` (lines 137-155)
- `crates/pvthfhe-pvss/src/lib.rs` — `PvssError` (lines 98-131)
- `crates/pvthfhe-aggregator/src/folding/mod.rs` — `FoldError` (line 99)
- Call sites in `adapter.rs`, `nizk_share.rs`, `nizk_decrypt.rs`, `encrypt.rs`, `dkg_aggregation.rs`

**Design**: Add `party_id: Option<u16>` to error variants that are produced during per-party operations. The `Option` accounts for errors that occur before party context is available (e.g., `InvalidInput` during deserialization). Error sites that DO have party context must populate it. The `Display` impl includes the party_id when present.

#### Concrete Code Changes

**Step 1 — TDD: Write RED tests**

File: `crates/pvthfhe-pvss/tests/` (new: `error_party_context.rs`)

```rust
use pvthfhe_pvss::PvssError;

#[test]
fn pvss_error_display_includes_party_id_when_present() {
    let err = PvssError::BfvEncryptionProofFailed { party_id: Some(7) };
    let msg = format!("{err}");
    assert!(msg.contains("party 7") || msg.contains("party_id=7"),
        "error display must include party id: {msg}");
}

#[test]
fn pvss_error_display_works_without_party_id() {
    let err = PvssError::InvalidShare { party_id: None };
    let msg = format!("{err}");
    assert!(msg.contains("invalid PVSS share"),
        "error display must work without party id: {msg}");
}
```

File: `crates/pvthfhe-nizk/tests/` (new: `error_party_context.rs`)

```rust
use pvthfhe_nizk::NizkError;

#[test]
fn nizk_error_display_includes_party_id() {
    let err = NizkError::VerificationFailed { reason: "test", party_id: Some(3) };
    let msg = format!("{err}");
    assert!(msg.contains("party 3") || msg.contains("party_id=3"),
        "error display must include party id: {msg}");
}
```

**Step 2 — GREEN: Implement fix**

File: `crates/pvthfhe-nizk/src/lib.rs`

Modify `NizkError`:
```rust
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NizkError {
    #[error("conditional soundness: {reason}")]
    ConditionalSoundnessDisclosure { reason: &'static str },

    #[error("invalid NIZK input: {reason}")]
    InvalidInput { reason: &'static str, party_id: Option<u16> },

    #[error("invalid NIZK proof: {reason}")]
    InvalidProof { reason: &'static str, party_id: Option<u16> },

    #[error("NIZK verification failed (party {party_id:?}): {reason}")]
    VerificationFailed { reason: &'static str, party_id: Option<u16> },

    #[error("proof generation failed (party {party_id:?}): {reason}")]
    ProofGenerationFailed { reason: &'static str, party_id: Option<u16> },
}
```

Update `NizkAdapter` trait in `lib.rs` — add `party_id` to `verify` and `prove`:
```rust
fn verify(&self, stmt: &NizkStatement, proof: &NizkProof, party_id: u16) -> Result<(), NizkError>;
```
(Or, if the trait is stable, keep the signature but have implementations populate `party_id` from `stmt.participant_id`.)

**Recommended**: Do NOT change the trait signature. Instead, have `CycloNizkAdapter::verify` extract `participant_id` from `stmt.participant_id` and populate error variants internally. This avoids breaking the trait boundary.

File: `crates/pvthfhe-pvss/src/lib.rs`

Modify `PvssError` — add `party_id: Option<u16>` to variants lacking it:
```rust
pub enum PvssError {
    InvalidShare { party_id: Option<u16> },
    RecoveryFailed { party_id: Option<u16> },
    BackendError(String),
    InvalidDomainSeparator { party_id: Option<u16> },
    StatementMismatch { party_id: Option<u16> },
    ChallengeVerificationFailed { party_id: Option<u16> },
    CiphertextVMismatch { party_id: Option<u16> },
    InvalidCommitmentStructure { party_id: Option<u16> },
    LatticeBindingVerificationFailed { party_id: Option<u16> },
    D2HashBindingFailed { party_id: Option<u16> },
    BfvEncryptionProofFailed { party_id: Option<u16> },
    SmudgeSlotReused { party_id: u16, slot_id: u16 },
    ShareVerification(String),
}
```

Update `Display` impl for `PvssError` (line 185) to include `party_id` when `Some`:
```rust
fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
        Self::InvalidShare { party_id } => write_with_party(f, "invalid PVSS share", *party_id),
        Self::RecoveryFailed { party_id } => write_with_party(f, "PVSS recovery failed", *party_id),
        // ... similar for other variants ...
    }
}

fn write_with_party(f: &mut fmt::Formatter<'_>, msg: &str, party_id: Option<u16>) -> fmt::Result {
    match party_id {
        Some(id) => write!(f, "{msg} (party {id})"),
        None => f.write_str(msg),
    }
}
```

File: `crates/pvthfhe-aggregator/src/folding/mod.rs`

Modify `FoldError`:
```rust
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub struct FoldError {
    pub message: String,
    pub party_id: Option<u16>,
}

impl fmt::Display for FoldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.party_id {
            Some(id) => write!(f, "fold error (party {id}): {}", self.message),
            None => write!(f, "fold error: {}", self.message),
        }
    }
}
```

Update all `FoldError(...)` construction sites in `folding/mod.rs` to `FoldError { message: ..., party_id: None }`.

**Step 3 — Update error construction sites**

Search for all `PvssError::InvalidShare`, `PvssError::RecoveryFailed`, etc. and add `party_id: Some(...)` where context is available.

Key files to update:
- `crates/pvthfhe-pvss/src/nizk_share.rs` — verification errors have `stmt.participant_id`
- `crates/pvthfhe-pvss/src/nizk_decrypt.rs` — same
- `crates/pvthfhe-pvss/src/encrypt.rs` — share encryption has party context
- `crates/pvthfhe-pvss/src/dkg_aggregation.rs` — aggregation knows which party's share failed
- `crates/pvthfhe-nizk/src/adapter.rs` — `CycloNizkAdapter::verify` has `stmt.participant_id`

Pattern at each error site:
```rust
// Before:
return Err(PvssError::BfvEncryptionProofFailed);
// After:
return Err(PvssError::BfvEncryptionProofFailed { party_id: Some(stmt.participant_id) });
```

**Step 4 — Verify**

```bash
cargo test -p pvthfhe-nizk
cargo test -p pvthfhe-pvss
cargo test -p pvthfhe-aggregator --features real-folding
```

---

### F5b: FoldError Construction Sites

All `FoldError(...)` calls in `folding/mod.rs` must be updated. Current pattern:
```rust
FoldError(format!("..."))
```

New pattern:
```rust
FoldError { message: format!("..."), party_id: None }
// Or with party context:
FoldError { message: format!("..."), party_id: Some(participant_id) }
```

**Files**:
- `crates/pvthfhe-aggregator/src/folding/mod.rs` — lines 158, 164, 171, 201 (and any others from `grep "FoldError(" `)

---

### F6: `.expect()` in NIZK Paths Destroy Blame Context

**Severity**: MEDIUM
**Files**:
- `crates/pvthfhe-pvss/src/nizk_share.rs` — lines 1378, 1394, 1600

**Root cause**: `compute_share_commitment` and `compute_share_commitment_tracked` use `.expect()` which panics instead of returning structured errors. `ShareNizkOpenedProof::encode_body` also uses `.expect()`.

#### Concrete Code Changes

**Step 1 — TDD: Write RED test**

File: `crates/pvthfhe-pvss/tests/` (add to existing nizk_share tests or new file)

```rust
#[test]
fn compute_share_commitment_returns_error_on_invalid_input() {
    // Test that compute functions return Result, not panic
    let result = pvthfhe_pvss::nizk_share::compute_share_commitment_result(
        b"session", usize::MAX, b""  // Edge case
    );
    // Should be Err, not panic
    assert!(result.is_err());
}
```

**Step 2 — GREEN: Implement fix**

File: `crates/pvthfhe-pvss/src/nizk_share.rs`

Lines 1372-1379: Replace `compute_share_commitment`:
```rust
/// Compute the share commitment via RLWE sigma D2 hash binding.
///
/// Returns `Err(PvssError::D2HashBindingFailed { party_id: None })` on failure
/// instead of panicking.
pub fn compute_share_commitment(
    session_id: &[u8],
    recipient_index: usize,
    share_bytes: &[u8],
) -> Result<[u8; DIGEST_LEN], PvssError> {
    compute_ajtai_d2_binding(session_id, recipient_index, share_bytes)
        .map_err(|_| PvssError::D2HashBindingFailed { party_id: None })
}
```

Lines 1387-1395: Replace `compute_share_commitment_tracked`:
```rust
pub fn compute_share_commitment_tracked(
    session_id: &[u8],
    recipient_index: usize,
    share_bytes: &[u8],
    track_domain_tag: &[u8],
) -> Result<[u8; DIGEST_LEN], PvssError> {
    compute_ajtai_d2_binding_tracked(session_id, recipient_index, share_bytes, track_domain_tag)
        .map_err(|_| PvssError::D2HashBindingFailed { party_id: None })
}
```

Line 1600: Replace `.expect()` in `encode_body`:
```rust
fn encode_body(&self) -> Vec<u8> {
    encode_opened_proof_body(self)
        .unwrap_or_else(|e| {
            // Log and return empty vec rather than panic.
            // Callers must handle empty proof bytes.
            tracing::error!("ShareNizkOpenedProof encode failed: {:?}", e);
            Vec::new()
        })
}
```

**Better alternative** for `encode_body`: Change the `WireFormat` trait to allow fallible encoding, or pre-validate the proof at construction time so encoding is infallible. The minimal fix is the `unwrap_or_else` above.

**Step 3 — Update call sites**

Find all callers of `compute_share_commitment` and `compute_share_commitment_tracked` and update them to handle the `Result`:

```bash
grep -rn "compute_share_commitment\|compute_share_commitment_tracked" crates/ --include="*.rs"
```

At each call site, change from:
```rust
let commitment = compute_share_commitment(session_id, idx, bytes);
```
to:
```rust
let commitment = compute_share_commitment(session_id, idx, bytes)
    .map_err(|e| PvssError::D2HashBindingFailed { party_id: Some(rcpt_id) })?;
```

**Step 4 — Verify**

```bash
cargo test -p pvthfhe-pvss
cargo test -p pvthfhe-aggregator
```

---

### F8: Opaque DkgError Loses Party Context

**Severity**: LOW
**Files**:
- `crates/pvthfhe-keygen/src/dkg.rs` — `DkgError` (lines 45-53)

#### Concrete Code Changes

Modify `DkgError`:
```rust
#[derive(Debug)]
pub enum DkgError {
    /// Underlying FHE backend error.
    Fhe { message: String, party_id: Option<u32> },
    /// Ceremony has not been run yet.
    NotInitialized,
    /// Invalid parameters supplied.
    InvalidParams(String),
}
```

Update `From<FheError>` impl (line 55):
```rust
impl From<FheError> for DkgError {
    fn from(e: FheError) -> Self {
        DkgError::Fhe { message: e.to_string(), party_id: None }
    }
}
```

Update `Display` impl (line 61):
```rust
impl core::fmt::Display for DkgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DkgError::Fhe { message, party_id } => match party_id {
                Some(id) => write!(f, "FHE error (party {id}): {message}"),
                None => write!(f, "FHE error: {message}"),
            },
            DkgError::NotInitialized => f.write_str("DKG ceremony not yet run"),
            DkgError::InvalidParams(msg) => write!(f, "invalid DKG params: {msg}"),
        }
    }
}
```

Update error construction sites in `dkg.rs`:
- Line 90: `DkgError::InvalidParams(format!(...))` — unchanged (no party context available)
- `partial_decrypt` (line 188): If it fails, wrap with `DkgError::Fhe { message: ..., party_id: Some(party_id) }`

**Verify**:
```bash
cargo test -p pvthfhe-keygen
```

---

## WORKSTREAM D: MPC ROUND TIMEOUTS (F7) — P2 MEDIUM

### F7: No MPC Round Timeouts

**Severity**: MEDIUM
**Files**:
- `crates/pvthfhe-keygen/src/dkg.rs` — `DkgCeremony`
- `crates/pvthfhe-aggregator/src/keygen/simulator.rs` — `KeygenSimulator::run`
- `crates/pvthfhe-cli/src/full_pipeline.rs` — existing `run_with_timeout()` pattern

**Design**: Add per-round timeout parameters to the DKG session configuration. When a round exceeds its timeout, the protocol aborts and returns a `BlameProof` against non-responsive parties. The timeout mechanism reuses the existing `run_with_timeout()` pattern from `full_pipeline.rs:3592`.

**Scope note**: This is the most complex fix. A full implementation requires:
1. Timeout configuration in `DkgParams`
2. Per-round timeout enforcement in `DkgCeremony::run` and `KeygenSimulator::run`
3. Tracking of which parties have responded
4. `BlameProof` generation on timeout

**Phase 1 (this plan)**: Add timeout parameters and abort-on-timeout semantics. The full `BlameProof` generation against non-responsive parties depends on F5 (error types with party context).

#### Concrete Code Changes

**Step 1 — TDD: Write RED test**

File: `crates/pvthfhe-keygen/tests/` (new: `dkg_timeout.rs`)

```rust
use pvthfhe_keygen::dkg::{DkgCeremony, DkgParams};
use std::time::Duration;

#[test]
fn dkg_params_rejects_zero_timeout() {
    let params = DkgParams {
        n: 5,
        t: 3,
        round_timeout: Some(Duration::from_secs(0)),
    };
    let result = DkgCeremony::new(params);
    assert!(result.is_err(), "zero timeout must be rejected");
}

#[test]
fn dkg_params_accepts_reasonable_timeout() {
    let params = DkgParams {
        n: 5,
        t: 3,
        round_timeout: Some(Duration::from_secs(30)),
    };
    let result = DkgCeremony::new(params);
    assert!(result.is_ok(), "reasonable timeout must be accepted");
}

#[test]
fn dkg_params_accepts_no_timeout() {
    let params = DkgParams {
        n: 5,
        t: 3,
        round_timeout: None,
    };
    let result = DkgCeremony::new(params);
    assert!(result.is_ok(), "no timeout (None) must be accepted");
}
```

**Step 2 — GREEN: Implement fix**

File: `crates/pvthfhe-keygen/src/dkg.rs`

Add `round_timeout` to `DkgParams`:
```rust
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct DkgParams {
    pub n: usize,
    pub t: usize,
    /// Per-round timeout. `None` means no timeout (research mode).
    /// `Some(Duration::ZERO)` is rejected.
    pub round_timeout: Option<Duration>,
}
```

Add timeout validation in `DkgCeremony::new` (line 88):
```rust
pub fn new(params: DkgParams) -> Result<Self, DkgError> {
    if params.t == 0 || params.t > params.n {
        return Err(DkgError::InvalidParams(format!(...)));
    }
    if let Some(timeout) = params.round_timeout {
        if timeout.is_zero() {
            return Err(DkgError::InvalidParams(
                "round_timeout must be positive".into()
            ));
        }
    }
    // ...
}
```

Store `round_timeout` in `DkgCeremony` struct:
```rust
pub struct DkgCeremony {
    // ... existing fields ...
    round_timeout: Option<Duration>,
}
```

**Step 3 — Protocol-level timeout integration**

In `KeygenSimulator::run` (`crates/pvthfhe-aggregator/src/keygen/simulator.rs`), add timeout-aware round execution. The `run` method already iterates through party rounds. Add:

```rust
/// Run the DKG with per-round timeouts.
pub fn run_with_timeout(
    &mut self,
    round_timeout: Option<Duration>,
) -> Result<KeygenResult, DkgError> {
    // For each round, check elapsed time against round_timeout.
    // On timeout:
    //   1. Collect set of parties that have NOT responded
    //   2. Return DkgError::RoundTimeout { round, missing_parties: Vec<u32> }
    // ...
}
```

Add `RoundTimeout` variant to `DkgError`:
```rust
pub enum DkgError {
    Fhe { message: String, party_id: Option<u32> },
    NotInitialized,
    InvalidParams(String),
    /// A protocol round timed out. `missing_parties` lists parties that
    /// did not respond within the timeout window.
    RoundTimeout {
        round: u8,
        missing_parties: Vec<u32>,
    },
}
```

**Note**: Full implementation of runtime timeout enforcement requires threading `Duration` through the simulator's round execution loop. This is a non-trivial change — the plan defers the full loop instrumentation to a follow-up workstream in the implementation phase. This plan delivers the data model changes (DkgParams, DkgError variants) as the foundation.

**Step 4 — Verify**

```bash
cargo test -p pvthfhe-keygen
cargo test -p pvthfhe-aggregator -- keygen
```

---

## WORKSTREAM E: HARDENING (F9, F10, F11) — P3 LOW

### F9: NonEquivSignature::from_bytes Uses G1Affine::new_unchecked

**Severity**: LOW
**Files**:
- `crates/pvthfhe-non-equiv/src/lib.rs` — `NonEquivSignature::from_bytes` (line 366)

**Fix**: Replace `new_unchecked` with `new` (which validates curve membership), or add explicit `is_on_curve()` check with error return.

#### Concrete Code Changes

Line 366:
```rust
// Before:
let sig_r = G1Affine::new_unchecked(rx, ry);
// After:
let sig_r = Option::from(G1Affine::new(rx, ry))
    .ok_or(NonEquivError::InvalidSignature(signer_id))?;
```

Add explicit test:
```rust
#[test]
fn test_deserialize_rejects_off_curve_point() {
    let mut bytes = [0u8; 100];
    bytes[0..4].copy_from_slice(&1u32.to_be_bytes()); // signer_id = 1
    // Fill rx, ry with values known to be off-curve
    bytes[4..36].fill(0xFF);
    bytes[36..68].fill(0xFF);
    bytes[68..100].fill(0);

    let result = NonEquivSignature::from_bytes(&bytes);
    assert!(result.is_err(), "off-curve point must be rejected at deserialization");
}
```

**Verify**:
```bash
cargo test -p pvthfhe-non-equiv
```

---

### F10: nizk_keygen decode_i64_vec Silent Return on Truncation

**Severity**: LOW
**Files**:
- `crates/pvthfhe-pvss/src/nizk_keygen.rs` — `decode_i64_vec` (line 134), `decode_u64_vec` (line 152)

**Fix**: Return `Result` with descriptive error instead of silently returning empty vector.

#### Concrete Code Changes

Modify `decode_i64_vec`:
```rust
fn decode_i64_vec(data: &[u8]) -> Result<Vec<i64>, PvssError> {
    if data.len() < 4 {
        return Err(PvssError::InvalidShare { party_id: None }); // was: return vec![]
    }
    let len = (u32::from_le_bytes(data[..4].try_into().unwrap_or([0u8; 4])) as usize)
        .min(MAX_KEYGEN_VEC_LEN);
    let elem_bytes = len.min((data.len() - 4) / 8) * 8;
    let mut out = Vec::with_capacity(len);
    for i in 0..(elem_bytes / 8) {
        let range = 4 + i * 8..4 + (i + 1) * 8;
        if let Some(bytes) = data.get(range) {
            out.push(i64::from_le_bytes(bytes.try_into().unwrap_or([0u8; 8])));
        }
    }
    out.resize(len, 0);
    Ok(out)
}
```

Apply same pattern to `decode_u64_vec` (line 152).

**Update call sites**: Find all callers of `decode_i64_vec`/`decode_u64_vec` and handle the `Result`:
```bash
grep -rn "decode_i64_vec\|decode_u64_vec" crates/ --include="*.rs"
```

**Verify**:
```bash
cargo test -p pvthfhe-pvss -- nizk_keygen
```

---

### F11: No Abort-Time Explicit State Reset API

**Severity**: LOW
**Files**:
- `crates/pvthfhe-fhe/src/fhers.rs` — `PartyState` and related types

**Fix**: Add `fn abort_session(&mut self)` to `FhersBackend` (or the party state wrapper) that explicitly zeroizes all secret material and resets the state machine. This complements the existing `ZeroizeOnDrop` by providing a programmatic abort hook callable before `Drop`.

#### Concrete Code Changes

Add to `FhersBackend`:
```rust
/// Abort the current session: zeroize all secret state and reset to pre-DKG state.
///
/// Call this when a protocol round fails or a party is blamed. Unlike `Drop`,
/// which runs whenever the struct leaves scope, this is an explicit API that
/// can be called at the precise point of protocol abort.
pub fn abort_session(&mut self) {
    // Zeroize per-party states
    for state in &mut self.party_states {
        state.zeroize();
    }
    self.party_states.clear();
    // Reset DKG state
    self.dkg_initialized = false;
}
```

Add test:
```rust
#[test]
fn abort_session_zeroizes_and_resets() {
    let mut backend = FhersBackend::load_params(TEST_PARAMS_TOML).unwrap();
    // Initialize DKG state
    // ...
    backend.abort_session();
    assert!(!backend.dkg_initialized);
    assert!(backend.party_states.is_empty());
}
```

**Verify**:
```bash
cargo test -p pvthfhe-fhe -- abort
```

---

## WORKSTREAM F: DOCUMENTATION (F12, F13) — INFO

### F12: No Cross-Instance Abort Propagation

**Status**: INFO — accepted as limitation. No code change.

**Action**: Add to `docs/OPEN-PROBLEM-BLOCKERS.md` or `SECURITY.md`:

```markdown
### F12: Cross-Instance Abort Propagation

**Status**: ACCEPTED LIMITATION (research prototype)

The PVTHFHE protocol is designed for single-process sequential execution (simulator mode). In a real multi-party deployment where each party runs independently, there is no mechanism for one party's abort to trigger cleanup on other parties' instances. Each party detects protocol failure independently through timeout or invalid-message rejection.

**Production path**: A real deployment would use a consensus-broadcast channel (e.g., Ethereum event logs) for abort signaling. This is out of scope for the research prototype.
```

### F13: FHE Wire Types Don't Validate Algebraic Coefficient Domains

**Status**: INFO — accepted as limitation. No code change.

**Action**: Add to `crates/pvthfhe-fhe/src/wire.rs` header doc:

```rust
//! ## RESEARCH LIMITATION (F13)
//!
//! Wire type deserialization (`KeygenShareV1`, `PublicKeyV1`, `DecryptShareV2`)
//! validates length bounds but does NOT validate that polynomial coefficient
//! bytes represent valid field elements (i.e., bytes < modulus for each RNS limb).
//! Invalid coefficients are caught later during cryptographic operations
//! (BFV decryption will fail or produce garbage).
//!
//! Full coefficient-domain validation is deferred to production hardening.
```

Update `SECURITY.md` to reference F12 and F13.

---

## KNOCK-ON EFFECTS AND REGRESSION RISKS

| Change | Risk | Mitigation |
|--------|------|------------|
| F1: `hash_round1_message` signature change | Breaks all 14 call sites in non-equiv tests + 2 in simulator | Run `cargo test -p pvthfhe-non-equiv -p pvthfhe-aggregator` before committing |
| F1: `schnorr_sign_with_session` vs `schnorr_sign` | Backward compatibility — PoP uses session-independent path | Keep both functions; PoP stays on old path |
| F2: `disperse` signature change | AVID not yet called externally — no regression risk | Verify `cargo test -p pvthfhe-pvss -- avid` |
| F3: `generate_rank` signature change | Internal to `leader_election.rs` — no external callers | All test call sites in same file; `cargo test -p pvthfhe-aggregator -- leader` |
| F4: `absorb(label, data)` signature change | Only used in cyclo tests | `cargo test -p pvthfhe-cyclo` |
| F5: Error variant restructuring | All match arms on `PvssError`, `NizkError`, `FoldError` break | Run full test suite; grep for all match sites |
| F6: `compute_share_commitment` → `Result` | All call sites must handle `Result` | Grep for call sites before/after |
| F7: `DkgParams` new field | `DkgParams` construction sites break | Only `DkgCeremony::new` — update defaults |
| F9: `new_unchecked` → `new` | `new()` returns `Option` — need error handling | Already in `Result` return path |
| F10: `decode_i64_vec` → `Result` | All decode call sites break | Limited to `nizk_keygen.rs` internal calls |
| F11: New `abort_session` method | Additive — no breakage | Only new code |

---

## FILE CHANGE MANIFEST

| File | Findings | Change Type |
|------|----------|-------------|
| `crates/pvthfhe-non-equiv/src/lib.rs` | F1, F9 | Signature changes, deser hardening |
| `crates/pvthfhe-nizk/src/schnorr.rs` | F1 | New session-aware functions, DESIGN comment |
| `crates/pvthfhe-pvss/src/avid.rs` | F2 | `session_id` parameter threading |
| `crates/pvthfhe-aggregator/src/leader_election.rs` | F3 | `session_id` parameter threading |
| `crates/pvthfhe-cyclo/src/fiat_shamir.rs` | F4 | `absorb` signature change with label+length |
| `crates/pvthfhe-cyclo/tests/cyclo_ternary_transcript.rs` | F4 | Test call site updates + new chunking test |
| `crates/pvthfhe-nizk/src/lib.rs` | F5 | `NizkError` variant restructuring |
| `crates/pvthfhe-pvss/src/lib.rs` | F5 | `PvssError` variant restructuring |
| `crates/pvthfhe-aggregator/src/folding/mod.rs` | F5 | `FoldError` struct restructuring |
| `crates/pvthfhe-pvss/src/nizk_share.rs` | F6 | `.expect()` → `Result`, compute function sigs |
| `crates/pvthfhe-keygen/src/dkg.rs` | F7, F8 | Timeout params, `DkgError` restructuring |
| `crates/pvthfhe-aggregator/src/keygen/simulator.rs` | F1, F7 | NonEquiv call site updates, timeout integration |
| `crates/pvthfhe-pvss/src/nizk_keygen.rs` | F10 | `decode_i64_vec` → `Result` |
| `crates/pvthfhe-fhe/src/fhers.rs` | F11 | `abort_session()` method |
| `crates/pvthfhe-fhe/src/wire.rs` | F13 | RESEARCH LIMITATION doc comment |
| `docs/OPEN-PROBLEM-BLOCKERS.md` or `SECURITY.md` | F12, F13 | Documentation of accepted limitations |

---

## VERIFICATION CHECKLIST

After all changes are implemented, run:

```bash
# Per-workstream verification
cargo test -p pvthfhe-non-equiv                    # F1, F9
cargo test -p pvthfhe-nizk -- schnorr              # F1
cargo test -p pvthfhe-pvss -- avid                 # F2
cargo test -p pvthfhe-aggregator -- leader         # F3
cargo test -p pvthfhe-cyclo                        # F4
cargo test -p pvthfhe-nizk                         # F5 (all tests)
cargo test -p pvthfhe-pvss                         # F5, F6, F10 (all tests)
cargo test -p pvthfhe-keygen                       # F7, F8
cargo test -p pvthfhe-fhe                          # F11
cargo test -p pvthfhe-aggregator --features real-folding  # F5 (folding)

# Full integration gate
just phase1-gate                                   # DKG pipeline
just phase2-gate                                   # PVSS pipeline
just phase3-gate                                   # Aggregator pipeline
just dkg-paper-gate                                # DKG paper subprotocols
just test-all                                      # Rust + Noir + Solidity
just demo-e2e                                      # n=10, t=4, all 14 steps
```

**Acceptance criteria**:
- [ ] All RED tests from this plan pass (were RED before fixes, GREEN after)
- [ ] No existing tests regress
- [ ] `just dkg-paper-gate` passes (NonEquiv, AVID, escrow, leader election)
- [ ] `just demo-e2e` passes (full 14-step pipeline)
- [ ] Error messages for verification failures include party IDs
- [ ] Cross-session replay tests reject replayed signatures/ranks/proofs
- [ ] `CycloTernaryTranscript::absorb` with different label+data combinations produces different challenges

---

## DOCUMENTATION UPDATES

1. **`SECURITY.md`**: Add entries for F12 (cross-instance abort propagation — accepted limitation) and F13 (wire coefficient domain validation — accepted limitation). Note F1 PoP session-independence design decision.

2. **`ARCHITECTURE.md`**: Update §DKG to note session-bound NonEquiv signatures and AVID Merkle trees.

3. **`crates/pvthfhe-fhe/src/wire.rs`**: Add RESEARCH LIMITATION doc comment for F13.

4. **`crates/pvthfhe-nizk/src/schnorr.rs`**: Add DESIGN comment at `pop_challenge` explaining intentional session-independence.

5. **`docs/papers/2026-1159.md`**: If applicable, add note about session-binding implementation detail.

---

*Plan drafted: 2026-06-12, Sisyphus Metis agent*
*Pending: Momus review*
