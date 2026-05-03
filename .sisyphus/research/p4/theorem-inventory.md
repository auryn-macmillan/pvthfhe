# P4 Theorem Inventory

This note inventories the baseline theorem statements required for the P4 PVSS key-generation component under the threat model in `.sisyphus/research/p4/threat-model.md`. The statements are intentionally informal and theorem-ready, but stop short of full proofs.

## P4-T1 — Correctness of BFV Public-Key Derivation

- **Theorem-ID**: P4-T1
- **Name**: Correctness
- **Informal Statement**: If all honest parties follow the P4 key-generation protocol and the public transcript verifies, then the aggregated key-generation output defines a valid BFV public key for the combined secret key material induced by the honest parties' secret shares. Equivalently, any authorized set of at least \(t\) honest shares reconstructs the unique underlying secret/public-key contribution consistent with the public commitments and ciphertexts in the accepted dealing. The theorem covers correctness of honest execution, not robustness against malicious aborts.
- **Reduction Sketch**: Reduce correctness to the threshold-sharing reconstruction guarantee and to completeness of the public consistency checks and proof objects. Show that an accepting honest transcript must be witness-consistent, then argue that witness consistency implies the BFV public key is algebraically well formed relative to the combined honest-share secret.
- **Threat-Model Dependency**: Corruption Model; Threshold; Public Verifiability; Network

## P4-T2 — Secrecy of Secret-Key Material

- **Theorem-ID**: P4-T2
- **Name**: Secrecy
- **Informal Statement**: Against any static PPT adversary corrupting fewer than \(t\) parties, the joint view of the adversary—including corrupted-party states, all public commitments, all ciphertexts, and the public transcript—computationally hides the honest parties' residual secret-key material. In particular, no unauthorized set of size at most \(t-1\) can distinguish the real shared secret/public-key contribution from a simulated one except with negligible advantage. The hiding guarantee is parameterized by the transcript interface exposed by the P4 threat model.
- **Reduction Sketch**: Use a simulation or game-hopping argument that replaces honest-party encrypted shares and transcript components with hybrids, then reduces any non-negligible distinguishing advantage to solving Ring-LWE in the underlying BFV/RLWE module. Threshold privacy ensures the adversary's share view is information-theoretically insufficient before the computational RLWE layer is attacked.
- **Threat-Model Dependency**: Corruption Model; Threshold; Public Verifiability; Simulator

## P4-T3 — Public Verifiability Soundness

- **Theorem-ID**: P4-T3
- **Name**: Public Verifiability Soundness
- **Informal Statement**: Except with negligible probability, any public transcript accepted by the P4 verification algorithm corresponds to a valid dealing for the claimed dealer, session, threshold, and participant set. That is, acceptance implies existence of an underlying witness consistent with the published commitments, ciphertext formation, and share distribution obligations, so an adversary cannot make an invalid dealing pass verification. The theorem is the semantic bridge from syntactic transcript checks to real dealing validity.
- **Reduction Sketch**: Reduce a forged accepting transcript to either breaking the binding/extractability property of the commitment/proof system or violating proof-of-knowledge style soundness for the published proof objects. The reduction extracts a witness from any accepting adversarial transcript and shows that failure of validity would contradict the assumed binding or knowledge soundness guarantee.
- **Threat-Model Dependency**: Public Verifiability; Corruption Model; Simulator

## P4-T4 — Robustness and Abort-with-Blame Soundness

- **Theorem-ID**: P4-T4
- **Name**: Robustness / Abort-with-Blame
- **Informal Statement**: If a dealer or participant deviates from the P4 protocol by publishing malformed dealing data, inconsistent openings, or conflicting authenticated messages, then an honest public verifier can derive blame evidence from the transcript that identifies the cheating party. Conversely, except with negligible probability, no honest party that followed the protocol is ever blamed by a valid blame verifier. Thus malicious behavior leads to attributable aborts rather than silent failure or false framing.
- **Reduction Sketch**: Show completeness of blame extraction for each covered deviation type by mapping every detectable inconsistency to a deterministic blame predicate over the authenticated transcript. Then prove false-blame soundness by reducing any successful framing attack against an honest party to either transcript forgery, authentication failure, or a soundness break in the public proof/consistency checks.
- **Threat-Model Dependency**: Abort with Blame; Network; Corruption Model; Public Verifiability

## P4-T5 — Sequential Composition with P1 Decrypt-Share Functionality

- **Theorem-ID**: P4-T5
- **Name**: Sequential Composition
- **Informal Statement**: The P4 ideal functionality \(F_{\mathrm{PVSS}}\), together with its simulator and transcript/corruption interface, composes sequentially with the P1 ideal functionality \(F_{\mathrm{NIZK\_DEC}}\) to realize a threshold BFV workflow that first performs public-verifiable key generation and then consumes the resulting key state for publicly verifiable decrypt-share generation. In the UC sense, any environment interacting with the sequential composition cannot distinguish it from the corresponding ideal-world execution except with negligible probability. The theorem covers sequential handoff of key material, party identities, corruption state, blame outcomes, and eligibility to decrypt.
- **Reduction Sketch**: Invoke UC sequential composition once the P4 simulator exports a transcript-consistent corruption interface and output state matching the assumptions required by the P1 simulator. Any distinguisher against the composed system can then be turned into a distinguisher against either the P4 realization of \(F_{\mathrm{PVSS}}\) or the P1 realization of \(F_{\mathrm{NIZK\_DEC}}\).
- **Threat-Model Dependency**: Simulator; Corruption Model; Abort with Blame; Network
