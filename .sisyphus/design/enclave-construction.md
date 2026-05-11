# R10.0 Enclave Attestation Construction Draft

Status: **draft — recommended pending oracle review**.

Scope: compare three TEE attestation constructions for PVTHFHE's ciphernode integrity requirement.

Non-scope: implementation, wire-format edits, circuits, Solidity, or plan updates.

---

## Context

PVTHFHE requires each ciphernode to prove it is running inside a genuine Trusted Execution Environment (TEE). The attestation verifier — part of the aggregator or a dedicated on-chain contract — must cryptographically verify that a ciphernode's key generation and partial decryption operations execute inside a measured, trusted enclave.

The current implementation in `crates/pvthfhe-enclave-adapter/src/lib.rs:114-116` returns `Ok(true)` unconditionally:

```rust
fn verify_proof(&self, _proof: &EnclaveProof, _public_inputs: &[u8]) -> Result<bool, String> {
    Ok(true)
}
```

This was catalogued as audit finding F64 (HIGH): any non-enclave actor can present as a valid ciphernode, collapsing the "decentralized confidential compute" security claim.

The Interfold threat model (`.sisyphus/design/threat-model-v1.md`) assumes:
- PPT active network adversary
- ≤ t−1 corrupted parties
- Ciphernodes running in attested TEEs as a defense-in-depth layer
- Attestation trust roots committed on-chain via `SessionRegistry.attestorRoots()`

The enclave-adapter is the integration boundary between the FHE protocol layer and the TEE attestation layer. It must:
1. Accept attestation evidence (quotes/reports) from ciphernodes
2. Verify the evidence against on-chain trust roots
3. Bind the attested identity to the protocol session (session_id, epoch, party_id)
4. Reject unverifiable or stale attestations

### Compatibility constraints

- **FHE backend**: Locked to `gnosisguild/fhe.rs` (`AGENTS.md` Backend Lock F1)
- **On-chain verifier**: `SessionRegistry` contract (R6); attestor roots managed via multisig + timelock (R6.4)
- **Noir circuits**: May consume attestation verification in future circuit iterations (R7 scope)
- **Deployment model**: Ciphernodes run on heterogeneous infrastructure (cloud VMs, bare metal, confidential compute nodes); single-backend lock-in is undesirable

---

## Candidates

### 1. Intel SGX DCAP (Data Center Attestation Primitives)

**Overview**: Process-level enclaves with precise code measurement via `MRENCLAVE` (enclave hash) and `MRSIGNER` (signing authority). DCAP provides ECDSA-based quote generation and verification without requiring a live Intel Attestation Service (IAS) — provisioning collateral (PCK certificates, TCB info, revocation lists) is fetched from Intel's Provisioning Certification Service (PCS) and can be cached for offline verification.

**Attestation flow**:
1. Ciphernode enclave generates an ECDSA quote over its measurement (MRENCLAVE, MRSIGNER), attributes (debug flag, mode), and report data (e.g., `H(session_id || party_id || ephemeral_pk)`)
2. Quote is signed by the platform's attestation key, chained to Intel's PCK root
3. Verifier fetches DCAP collateral (PCK cert chain, TCB info, QE identity, CRLs) from PCS or a local cache
4. Verifier calls `sgx_qv_verify_quote()` from the Intel DCAP Quote Verification Library (QVL) or the Quote Verification Enclave (QvE)
5. On success, the verifier extracts MRENCLAVE and compares against a known-good measurement whitelist

**Rust bindings**:
- Intel official: `intel/confidential-computing.tee.dcap` → `dcap_quoteverify-rs` (safe wrapper around C QVL; supports both SGX and TDX quote verification via `tee_verify_quote`)
- Community bindings: `mc-sgx-dcap-quoteverify` (MobileCoin fork; idiomatic Rust wrappers; battle-tested in production consensus systems)
- Build requirements: Intel SGX SDK, SgxSSL (OpenSSL fork for enclaves), QvE signed enclave binary

**Strengths**:
- **Finest-grained measurement**: Verifies the exact ciphernode binary, not just the VM. This matches PVTHFHE's "small trusted core" model perfectly.
- **Offline verification**: DCAP collateral can be fetched once and cached; no runtime dependency on a live Intel service. Critical for decentralized verification.
- **Production Rust bindings**: MobileCoin has production deployments using `mc-sgx-dcap-quoteverify` in a consensus-critical path since ~2021.
- **TDX unification**: Intel's `tee_verify_quote` API now handles both SGX and TDX quotes with a unified interface (DCAP 1.17+). Future-proofs for TDX migration.
- **Report data binding**: ECDSA quotes include 64 bytes of user-defined report data, sufficient for `H(session_id || party_id)` binding.

**Weaknesses**:
- **Hardware dependency**: Requires Intel CPUs with SGX support (Ice Lake Xeon or newer for DCAP; older SGX1 platforms insufficient)
- **Memory limits**: EPC (Enclave Page Cache) limits the protected memory to ~512 MB (V1) or ~1 TB (V2 with TDX); BFV operations with N=8192 are well within limits
- **Side-channel attacks**: SGX has a history of speculative-execution side channels (Foreshadow/L1TF, Plundervolt, ÆPIC Leak). Mitigations exist but require firmware patching and careful enclave coding
- **Syscall overhead**: Enclave transitions (ECALL/OCALL) impose single-digit microsecond overheads per call; acceptable for the low-frequency operations in PVTHFHE (keygen once per epoch, partial-decrypt once per ciphertext)
- **Build toolchain complexity**: Requires Intel SGX SDK and SgxSSL; not a standard `cargo build` dependency

**Suitability rating**: ★★★★★ (best match for PVTHFHE's "small trusted core" ciphernode model)

---

### 2. AMD SEV-SNP (Secure Encrypted Virtualization — Secure Nested Paging)

**Overview**: VM-level protection that encrypts guest memory from the hypervisor and provides integrity protection via reverse-map tables. SEV-SNP attestation verifies that a confidential VM booted with the expected initial measurement and guest policy, on genuine AMD hardware.

**Attestation flow**:
1. Guest VM requests an attestation report from the AMD Secure Processor (AMD-SP) via `SNP_GUEST_REQUEST`
2. Report includes: launch measurement (initial VM image hash), guest policy (debug, migration, SMT bits), platform TCB version, and a user-specified 64-byte report data
3. Report is signed with the Versioned Chip Endorsement Key (VCEK), unique per CPU and TCB version
4. Verifier fetches VCEK certificate from AMD's Key Distribution Service (KDS) and validates the certificate chain
5. On success, verifier compares launch measurement and guest policy against known-good reference values

**Rust bindings**:
- No official Intel-style Rust SDK for SEV-SNP attestation
- `sev` crate (VirTEE/Enarx project): provides SNP guest request protocol, VCEK certificate fetching, and attestation report parsing
- Cloud-specific SDKs: Azure `guest-attestation` client library, GCP Confidential Space attestation token verification

**Strengths**:
- **Broader hardware availability**: AMD EPYC (Milan 7003, Genoa 9004) processors are widely available across AWS (EC2), Azure (DCasv5/ECasv5), and GCP (C2D/N2D)
- **Lift-and-shift ergonomics**: Run standard Linux guests without application-level refactoring; the ciphernode binary runs as a normal process inside the confidential VM
- **Larger trust boundary**: Full VM protection means the OS and runtime (e.g., Rust std) are inside the TCB, which simplifies deployment but enlarges the attack surface
- **No EPC limits**: Full system RAM available to the guest; no SGX-style memory constraints

**Weaknesses**:
- **Coarser granularity**: Attestation measures the VM image, not the specific application binary. A compromised guest OS after boot could substitute a malicious ciphernode binary without detection (unless a higher-level application measurement layer is added, e.g., vTPM PCRs or IMA)
- **No post-boot integrity**: SEV-SNP does not provide continuous integrity monitoring after launch; runtime memory corruption attacks (e.g., Rowhammer variants) are outside the trust boundary
- **Rust ecosystem immaturity**: The `sev` crate is maintained by the Enarx project (Red Hat) but has less production deployment history than SGX's DCAP Rust bindings
- **Live KDS dependency**: VCEK certificate fetching requires reaching AMD's KDS; caching strategies exist but are less mature than DCAP PCS caching
- **Interrupt-injection attacks**: Recent research (Heckler/WeSee, 2024) demonstrated that malicious hypervisors can inject interrupts to corrupt SNP VM state at the interrupt boundary. Mitigations require updated firmware and hypervisor-level tuning

**Suitability rating**: ★★★☆☆ (good for deployment flexibility, weaker for application identity)

---

### 3. AWS Nitro Enclaves

**Overview**: AWS-specific isolated microVM with no persistent storage, no network interface, and a virtual socket (vsock) for communication with the parent instance. Attestation is provided via a signed attestation document that binds the enclave's measurements (PCRs) to an AWS Nitro PKI root.

**Attestation flow**:
1. Enclave requests an attestation document from the Nitro hypervisor via `/dev/nsm`
2. Document includes: PCR0 (enclave image SHA-384, the EIF hash), PCR1 (Linux kernel + bootstrap), PCR2 (application), and optionally user-provided nonce/public-key for freshness binding
3. Document is signed in COSE (CBOR Object Signing and Encryption) format, chained to the AWS Nitro root CA
4. Verifier (or AWS KMS) validates the document's signature chain and checks PCRs against a known-good policy
5. AWS KMS can directly enforce attestation-bound key release: a KMS key policy can require that decryption operations are only permitted when the caller presents a valid enclave attestation document with specific PCR values

**Rust bindings**:
- `aws-nitro-enclaves-cose`: COSE signing/verification for attestation documents
- `aws-nitro-enclaves-nsm-api`: Rust bindings for the Nitro Secure Module driver
- Both maintained in the `aws/aws-nitro-enclaves-sdk-c` repository with Rust wrappers

**Strengths**:
- **Tight KMS integration**: AWS KMS natively supports attestation-bound key release policies; the ciphernode's BFV key material can be sealed such that only a verified enclave can unwrap it
- **Managed infrastructure**: No SGX SDK build complexity; enclaves are Docker images converted to EIFs via `nitro-cli build-enclave`
- **vsock isolation**: No TCP/IP stack inside the enclave; communication is via a local vsock proxy, reducing network attack surface

**Weaknesses**:
- **AWS-only lock-in**: Nitro Enclaves only run on AWS; deploying ciphernodes on other clouds or bare metal requires a completely different attestation stack
- **AWS root of trust**: The attestation trust root is AWS's PKI, not the CPU vendor's silicon root. This adds AWS as a trusted party in the attestation chain (though this is consistent with AWS's shared responsibility model)
- **Less precise measurement**: PCR2 (application) measures the entire filesystem and command; changes to any dependency file change the PCR, making reproducible builds essential
- **No defense against a compromised parent**: The parent EC2 instance provisions the enclave; if the parent is compromised, it can refuse to launch enclaves or tamper with vsock traffic (though it cannot read enclave memory)

**Suitability rating**: ★★☆☆☆ (excellent for cloud-managed deployments, unacceptable for multi-cloud portability requirement)

---

### 4. Multi-backend attestation (SGX DCAP + SEV-SNP)

**Overview**: Define an `AttestationVerifier` trait in `pvthfhe-enclave-adapter` with backends for SGX DCAP and AMD SEV-SNP. On-chain trust roots are stored per-backend in `SessionRegistry.attestorRoots[backend_id]`. The aggregator or verifier contract selects the appropriate verifier based on the ciphernode's declared backend.

**Architecture**:
```
trait AttestationVerifier {
    type Quote;
    type Collateral;
    type TrustRoot;

    fn verify(
        quote: &Self::Quote,
        collateral: &Self::Collateral,
        trust_root: &Self::TrustRoot,
        expected_measurement: &[u8; 32],
        binding_data: &[u8],
    ) -> Result<AttestationResult, AttestationError>;
}

struct SgxDcapVerifier { ... }
struct SevSnpVerifier { ... }
```

**Trust root management**:
- Attestation trust roots (SGX MRSIGNER whitelist, SEV-SNP VCEK cert chain roots) are committed on-chain via the `SessionRegistry` contract
- `addAttestor(bytes32 backendId, bytes32 root)` is gated by the `ATTESTOR_MANAGER` role, itself behind a 2-of-3 multisig + 48h timelock (R6.4)
- Trust roots are per-epoch: the root committed at epoch `e` is the root valid for all sessions in that epoch
- `dkg_root` binds the attestor set: `dkg_root = H(all_attestor_roots || participant_set_hash)`

---

## Recommendation

**Selected construction: SGX DCAP primary with multi-backend abstraction layer (Option 4)**.

### Primary rationale

1. **Measurement precision**: SGX DCAP is uniquely capable of verifying a specific ciphernode binary identity (MRENCLAVE). SEV-SNP measures the VM image, not the application — adding a vTPM or IMA layer to achieve comparable precision is more complex than running the ciphernode directly as an SGX enclave.

2. **Offline verification**: DCAP collateral (PCK certificates, TCB info, CRLs) can be pre-fetched and cached. Combined with on-chain trust root commitments, this enables fully decentralized verification without a live dependency on Intel's PCS. SEV-SNP requires AMD KDS for VCEK certificate freshening.

3. **Rust ecosystem maturity**: `mc-sgx-dcap-quoteverify` has been used in production by MobileCoin since ~2021 for consensus-critical enclave attestation. Intel's official `dcap_quoteverify-rs` provides safe wrappers for the Quote Verification Library. No SEV-SNP Rust library has comparable production deployment history.

4. **Small TCB alignment**: PVTHFHE's ciphernode workload (keygen_share, partial_decrypt) involves a narrow interface: generate key share, produce partial decryption. This is naturally expressed as a small SGX enclave with ~5 ECALLs and ~2 OCALLs (RNG, attestation fetching). The memory footprint of BFV operations with N=8192 fits comfortably within SGX EPC limits.

5. **Future extensibility**: The multi-backend abstraction ensures SEV-SNP and potentially Intel TDX can be added without re-architecting the protocol layer. On-chain trust roots are already partitioned by `backend_id`.

### Migration path to SEV-SNP (v2)

When SEV-SNP Rust attestation libraries mature and/or ciphernode operators demand non-Intel deployments:
1. Implement `SevSnpVerifier` against the `AttestationVerifier` trait using the `sev` crate's attestation report parsing + VCEK validation
2. Add an application-level measurement layer inside the SNP VM (e.g., TPM PCRs via `systemd-measure` or a boot-chain measurement log)
3. Commit new trust roots on-chain for `backend_id = SEV_SNP`
4. Ciphernodes declare their backend in the protocol handshake; aggregator selects the appropriate verifier

### Deferred decisions

- **TDX support**: Intel TDX unifies SGX-style quoting with VM-level abstraction via the `tee_verify_quote` API. TDX support is a natural evolution of the SGX DCAP path and does not require a separate backend. Defer to v2.
- **Nitro Enclaves**: Strongly discouraged for the reference implementation due to cloud lock-in. Individual ciphernode operators may use Nitro at their own risk, but the protocol's reference verifier will not include a Nitro attestation backend.
- **Arm CCA (Realm)**: Not yet generally available on cloud instances. Defer to v2+.
- **On-chain quote verification**: Verifying raw SGX ECDSA quotes or SEV-SNP attestation reports on-chain (EVM) is prohibitively expensive (gas costs for RSA/ECDSA signature verification + certificate chain parsing). The initial design verifies quotes off-chain in the Rust adapter; future work may explore zk-wrapped attestation (zkDCAP pattern) for on-chain verification.

### Residual risks

| Risk | Mitigation |
|------|------------|
| SGX side-channel attacks (ÆPIC, Plundervolt) | Require firmware attestation; SGX TCB recovery via microcode update; DCAP TCB info includes `tcbStatus` that verifier checks against a minimum acceptable TCB level |
| Physical attacks (WireTap DDR interposer) | Outside PVTHFHE's threat model (assumes data-center physical security); documented as an explicit scope boundary in `.sisyphus/design/threat-model-v1.md` |
| Intel PCS availability | DCAP collateral is cached and versioned; verifier uses most-recent-cached collateral if PCS is unreachable, with staleness bounds enforced by `collateral_expiration_status` |
| Multi-backend complexity | Only SGX DCAP is implemented in v1; the `AttestationVerifier` trait exists as an abstraction seam but has a single implementation |

---

## References

- Intel SGX DCAP Reference: https://github.com/intel/SGXDataCenterAttestationPrimitives
- Intel DCAP Quote Verification Library (QVL): https://github.com/intel/confidential-computing.tee.dcap.qvl
- MobileCoin DCAP Rust bindings: https://docs.rs/mc-sgx-dcap-quoteverify
- AMD SEV-SNP Attestation: https://www.amd.com/system/files/TechDocs/56860.pdf (SEV-SNP ABI §7.3)
- AMD SEV Rust crate: https://docs.rs/sev (VirTEE/Enarx project)
- AWS Nitro Enclaves Attestation: https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html
- IETF RATS EAT (Entity Attestation Token): https://datatracker.ietf.org/doc/draft-ietf-rats-eat/
- IETF CoRIM (Concise Reference Integrity Manifest): https://datatracker.ietf.org/doc/draft-ietf-rats-corim/
- zkDCAP concept: Phala/TOKI SGX attestation via zkVM — see https://github.com/Phala-Network
- "Confidential Computing VMs Explained" — SEV-SNP vs TDX empirical analysis: https://dse.in.tum.de/wp-content/uploads/2024/11/sigmetrics25summer-CVM-Explained.pdf
- "TEE + ZK: Where Trust Ends and Verification Begins" — 7BlockLabs (2025-10-06): https://www.7blocklabs.com/blog/tee-zk-where-trust-ends-and-verification-begins
- Audit finding F64: `.sisyphus/audit/AUDIT-2026-05-08.md` line 701
- AGENTS.md Backend Lock F1 (2026-05-04): `gnosisguild/fhe.rs`
- Threat model: `.sisyphus/design/threat-model-v1.md`

---

*Design doc authored: 2026-05-09. Oracle review pending.*
