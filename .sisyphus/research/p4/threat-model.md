# P4 Threat Model: PVSS Keygen

This document fixes the adversary model and security interfaces for the P4 PVSS key-generation component. It is written to support later theorem statements in the Random Oracle Model (ROM), with Quantum Random Oracle Model (QROM) extensions treated as a stretch goal, against probabilistic polynomial-time (PPT) adversaries.

## Corruption Model

Let the participant set be indexed by $[n] = \{1,\dots,n\}$. The default adversary is a static PPT adversary that commits to a corruption set $C \subseteq [n]$ before protocol start. The baseline honest-majority assumption is $|C| \le \lfloor n/2 \rfloor$, equivalently at least $t = \lfloor n/2 \rfloor + 1$ parties remain honest throughout the execution.

The baseline behavioral model for corrupted parties is malicious: a corrupted dealer or participant may send malformed ciphertexts, inconsistent openings, selective omissions, or invalid proof material, and may coordinate all such deviations adaptively within the fixed corruption set. Semi-honest corruption is treated only as a weaker special case in which corrupted parties follow the message schedule but retain their full internal view.

Adaptive corruption is a stretch goal rather than a baseline guarantee. Any adaptive extension must specify forward-security or erasure assumptions for dealer randomness, participant decryption randomness, and any witness material used in public proofs, because otherwise post-facto state exposure can invalidate simulation.

For theorem statements, the corruption interface should distinguish at minimum: corrupt dealer, corrupt participant, and corrupted verifier-observer. The last class does not alter protocol messages but is allowed arbitrary access to the public transcript. Security claims for P4 are therefore parameterized by $(n,t,C)$ with $t = \lfloor n/2 \rfloor + 1$ and $|C| \le t-1$.

## Threshold

The reconstruction threshold is fixed to

$$
t = \lfloor n/2 \rfloor + 1,
$$

so the system tolerates at most $t-1 = \lfloor n/2 \rfloor$ corruptions. All soundness, privacy, and liveness predicates for P4 should be stated relative to this threshold.

The deployment sizes considered in the current program are

$$
n \in \{128, 512, 1024\}.
$$

For each such $n$, the PVSS dealing distributes shares using Shamir secret sharing over an appropriate ring or field chosen by the later protocol construction. This threat model does not fix that algebraic instantiation; it only assumes that the share space supports a threshold sharing relation with uniqueness of reconstruction from any valid $t$ shares and privacy against any set of size at most $t-1$.

Accordingly, a future theorem may quantify over any authorized set $H \subseteq [n]$ with $|H| \ge t$ and any unauthorized set $U \subseteq [n]$ with $|U| \le t-1$. Correctness requires that honest reconstruction from a valid dealing and any authorized set outputs the unique shared secret or derived public-key contribution. Privacy requires that the joint view of any unauthorized set reveals no more than the public transcript permits.

## Public Verifiability

P4 is publicly verifiable in the strong sense that anyone, including non-participants, can verify a dealer transcript without access to private shares or private interaction. Verification is non-interactive once the dealer has published its public transcript, meaning a verifier only evaluates deterministic checks over public data and any designated proof objects.

For formal use, define a dealer transcript $\tau_D$ to be a valid dealing if and only if all of the following hold:

1. $\tau_D$ contains a complete public statement identifying the dealer, session identifier, participant set, threshold, and all public commitments/ciphertexts required by the scheme.
2. Every public consistency check specified by the construction accepts on input $\tau_D$.
3. Every required proof object in $\tau_D$ verifies with respect to the public statement and transcript.
4. There exists an underlying witness consistent with the claimed share distribution, ciphertext formation, and public commitments for all honest recipients.

Item (4) is the semantic validity condition that later soundness theorems should prove from items (2) and (3). Thus public verifiability for P4 means that acceptance by the public verification algorithm implies that the dealer has produced a dealing that is well-formed with respect to the intended threshold-sharing relation except with negligible probability.

This definition deliberately avoids fixing the proof system or ciphertext structure. It is enough for theorem statements to say that any PPT verifier given $\tau_D$ either accepts a valid dealing or rejects, and that acceptance is publicly reproducible from the transcript alone.

## Abort with Blame

P4 follows an abort-with-blame model rather than a guaranteed-completion model. If a dealer or participant cheats by publishing a bad dealing, a bad opening, or any inconsistent response, the protocol may abort, but it must also output publicly checkable blame evidence bound to an authenticated party identity.

Blame evidence is any public tuple $\beta = (\mathsf{id}, \mathsf{stmt}, \mathsf{aux})$ such that any verifier can run a deterministic verification algorithm on $(\tau, \beta)$ and conclude that party $\mathsf{id}$ violated a protocol obligation encoded by statement $\mathsf{stmt}$. Typical obligations include malformed public dealing data, a decryption/opening that fails public consistency, or an equivocation between two authenticated messages in the same session. The exact syntax of $\beta$ is deferred to the construction, but the threat model requires that blame evidence be publicly verifiable and replayable from the transcript.

Liveness is constrained as follows: honest parties are not blamed. Formally, except with negligible probability over protocol randomness and any proof-system soundness error, no blame verifier should accept evidence against an honest party that followed the protocol. This is the non-frameability condition needed for meaningful accountability.

The model permits aborts caused by network failure within the allowed network assumptions or by too many corruptions. It does not permit silent failure by an adversary that causes an abort without leaving attributable evidence when the failure arose from an authenticated malicious action covered by the protocol's blame predicates.

## Network

The primary network model is synchronous. Execution is divided into bounded rounds, and every message sent by an honest party in round $r$ is delivered to its intended honest recipients by the start of round $r+1$. This is the baseline liveness regime for P4 theorem statements.

The fallback model is partial synchrony: there exists an unknown global stabilization time after which the same bounded-delay guarantee holds. Under partial synchrony, safety properties should remain unchanged, while liveness statements should be conditioned on stabilization and on continued honest-majority participation.

The communication substrate must provide authenticated point-to-point delivery and an authenticated broadcast channel (or equivalent common transcript mechanism) for public dealer outputs, complaints/openings, and blame evidence. Message delivery guarantees required by the threat model are:

1. Integrity: honest recipients can attribute each delivered message to a unique sender identity.
2. Agreement on broadcast transcript: honest observers see the same ordered public transcript for all broadcast items in a session.
3. Timely delivery in the synchronous baseline, or eventual timely delivery after stabilization in the fallback model.

The adversary may rush within a round, delay messages up to the permitted bound, and schedule corrupt-party sends adversarially, but may not forge authenticated messages from honest parties or cause transcript divergence among honest observers without breaking the underlying authentication or broadcast assumptions.

## Simulator

The intended proof style for P4 is simulation-based, in the UC spirit, though this document gives only the informal simulator obligations. Define an ideal functionality $F_{\mathrm{PVSS}}$ that accepts dealer inputs for a threshold-sharing instance, delivers the corresponding public transcript interface to all parties and observers, enforces validity or abort-with-blame outcomes, and exposes corruption events through an explicit corruption API.

At minimum, a simulator for $F_{\mathrm{PVSS}}$ must handle two baseline cases: a corrupt dealer and a corrupt participant. For a corrupt dealer, the simulator must extract or otherwise account for the effective shared secret/public-key contribution represented by the accepted transcript, or force the ideal functionality to reject and emit blame if the transcript is invalid. For a corrupt participant, the simulator must explain any public opening, complaint, or blame interaction while preserving indistinguishability for honest-party views and transcript observers.

The simulator must also preserve public verifiability: the simulated transcript seen by external verifiers should be distributed indistinguishably from a real transcript, subject to the public acceptance or rejection outcome mandated by $F_{\mathrm{PVSS}}$. In particular, the simulator must expose enough structure for later proofs of completeness, soundness, privacy against sets of size at most $t-1$, and accountability/non-frameability.

For composition, $F_{\mathrm{PVSS}}$ must export the public-key material, party identities, corruption state, and any blame outcomes in a form consumable by the downstream decryption-share functionality $F_{\mathrm{DEC}}$ from P1. The composition note is mandatory: "The P1 threat model (decrypt-share NIZK) will extend this model by adding an additional corruption type for malicious decryptors. Any simulator for F_PVSS must expose a consistent corruption interface to allow sequential composition."

Thus the sequential composition obligation is that a simulator for P4 can hand off a transcript-consistent corruption state to the P1 simulator without ambiguity about which parties are corrupted, blamed, excluded, or still eligible to provide downstream decryption shares.
