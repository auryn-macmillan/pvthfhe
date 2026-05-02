# Threshold Decryption Protocol Specification (Architecture B)

## Core Parameters & Key Shape
- **Aggregate public key**: pk = Σᵢ pkᵢ (sum of individual public keys)
- **Secret shares**: Each party Pᵢ holds secret share skᵢ (short ternary vector in Rq)
- **Threshold**: t = ⌊N/2⌋+1 parties needed for decryption
- **Wire format**: CBOR-encoded, length-prefixed with 4-byte big-endian header

## Protocol Inputs
- Ciphertext: ct = (c₀, c₁) ∈ Rq²
- Aggregate public key: pk
- Threshold: t
- Participant set: S ⊆ [N] with |S| ≥ t

## Per-party algorithm
Executed by each Pᵢ ∈ S:
1. **Partial decryption**: Compute dᵢ = c₁ · skᵢ + eᵢ where eᵢ ← χ_smudge (smudging noise)
2. **NIZK Generation**: Compute NIZK proof πᵢ proving: "∃ skᵢ, eᵢ such that dᵢ = c₁ · skᵢ + eᵢ AND skᵢ is short AND eᵢ is short"
   - This is the RLWE-relation proof.
   - Proven via LatticeFold+ accumulator (Note: open problem P1 — flag soundness).
3. **Broadcast**: Emit payload: `DecryptShare { party_id: u32, share: RlweShare, nizk: NizkDecShare, version: u8 }`
   - Wire format: CBOR-encoded, length-prefixed with 4-byte big-endian header.

## Aggregator algorithm
Executed by any party or external relayer (MUST be treated as potentially malicious):
1. **Collect**: Wait for ≥t valid shares {(dᵢ, πᵢ)}ᵢ∈S'
2. **Verify**: For each share, verify πᵢ; if invalid, exclude Pᵢ and blame publicly.
3. **Fold**: Fold all valid NIZKs π₁…πₜ using LatticeFold+ into accumulator acc.
4. **Compress**: Compress acc into UltraHonk SNARK Π via MicroNova.
5. **Aggregate**: Compute aggregate partial decryption D = Σᵢ∈S' dᵢ (sum of valid shares).
6. **Decrypt**: Compute plaintext m = c₀ + D mod q, then round to plaintext space.
7. **Output**: `DecryptResult { plaintext: PlaintextPoly, proof: UltraHonkProof, participant_set: Vec<u32>, version: u8 }`

## Public verifier algorithm
Stateless, on-chain, NO access to any secret participant data:
1. **Inputs**: ct, plaintext m, proof Π, pk, public params pp.
2. **Verify Proof**: Verify UltraHonk proof Π (BB-generated verifier).
3. **Check Threshold**: Verify Π proves that ≥t parties each provided a valid RLWE partial decryption share.
4. **Check Consistency**: Verify aggregate D = Σ shares is consistent with m = c₀ + D mod q.
5. **Decision**: Accept if all checks pass; reject otherwise.
6. **CRITICAL**: The verifier MUST NOT require any secret shares — all verification is via the SNARK.

## Noise smudging parameters
- Smudging noise eᵢ ← χ_smudge where χ_smudge = discrete Gaussian with σ_smudge = 2^40 · σ_err
- This ensures statistical indistinguishability of dᵢ from uniform (hides the party's secret).
- Noise budget impact: smudging adds log₂(t · σ_smudge) ≈ 40 + log₂(t) bits to noise.
- At t=512: noise addition ≈ 49 bits; noise budget remaining ≈ 157 - 49 = 108 bits (safe).

## Failure modes
| Failure Mode | Detection | Blame Target | Recovery |
|---|---|---|---|
| Malformed NIZK πᵢ | Aggregator verifies πᵢ → fails | Party Pᵢ | Exclude Pᵢ, proceed if ≥t remain |
| Missing share | Timeout after Δ | Silent party Pᵢ | Exclude Pᵢ, proceed if ≥t remain |
| Share inconsistent with pk | Verifier rejects Π | Aggregator (blame) | Re-run with different aggregator |
| Replay attack | Nonce/epoch check fails | Replaying party | Reject, log |
| Aggregator equivocation | Two different DecryptResults for same ct | Aggregator | Publish both as evidence, slash |
