# Threat Model: Publicly Verifiable Threshold FHE

This document outlines the security parameters and adversarial assumptions for the PVTHFHE scheme.

## 1. Adversary Class
The protocol assumes a static malicious adversary with rushing capabilities.
- **Static**: The adversary chooses the set of corrupted parties before the protocol starts.
- **Malicious**: Corrupted parties can deviate arbitrarily from the protocol, send incorrect data, or refuse to participate.
- **Rushing**: In any given round, the adversary can wait to receive all messages from honest parties before sending its own messages.

## 2. Corruption Model
The scheme operates under an honest-majority threshold.
- **Threshold**: t = ⌊n/2⌋+1.
- **Secrecy**: Security holds against any coalition of strictly fewer than t parties. Specifically, any set C of corrupted parties where |C| ≤ t-1 (which is ⌊n/2⌋) learns nothing about the underlying plaintext.
- **Reconstruction**: Successful decryption and plaintext recovery require at least t honest parties (or a combination of parties including at least t shares) to participate correctly.
- **Abort-with-public-blame**: If any party cheats by submitting invalid shares or incorrect proofs, the protocol aborts, and the malicious party is publicly identified.
- **Formal Secrecy Predicate**: ∀ adversary A corrupting set C with |C| < t, A cannot distinguish Enc(m₀) from Enc(m₁) with non-negligible advantage.
- **Formal Reconstruction Predicate**: ∀ honest set H with |H| ≥ t, the threshold decryption protocol outputs the correct plaintext.

## 3. Network Model
We assume authenticated point-to-point channels and authenticated echo-broadcast (Bracha broadcast or equivalent).
- **Synchronous Rounds**: The prototype assumes a synchronous network where messages sent in a round are received by the start of the next round.
- **Authentication**: All communication is authenticated via MACs or digital signatures.
- **Availability**: The adversary can delay messages within the bounds of the synchronous model but cannot drop messages between honest parties.

## 4. Identity Assumption
The protocol relies on a Public-Key Infrastructure (PKI).
- **Long-term Keys**: Each participant possesses a long-term signing key pair.
- **Known Identities**: Public keys for all n parties are known and verified by all participants before the protocol begins.
- **No Anonymity**: Every message in the transcript is linked to a specific, authenticated identity.

## 5. Liveness and Safety Split
- **Safety (Secrecy + Soundness)**: Holds unconditionally as long as the number of corruptions is strictly less than t (≤ t-1).
- **Liveness (Termination)**: Guaranteed only when at least t honest parties are active and following the protocol. If the number of honest parties drops below t, the protocol may abort.
- **Robustness**: The protocol does not guarantee completion in the presence of faults (non-robust). Instead, it uses the abort-with-public-blame mechanism to ensure that failures are attributable.

## 6. Abort Model
The protocol implements Abort-with-public-blame.
- **Verifiability**: Any external observer (verifier) can audit the public transcript.
- **Blame Assignment**: If a party submits an invalid share or an invalid Zero-Knowledge Proof (ZKP), the transcript provides sufficient evidence to identify the cheater.
- **Recovery**: Upon an abort, honest parties can exclude the blamed party and restart the protocol if the honest-majority condition still holds.
