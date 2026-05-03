# P3 Frozen Interface Spec (On-Chain Verifier API)

This document freezes the P3 on-chain verifier boundary that consumes the P2 `FinalProof` output and the fixed P2→P3 public-input bundle. The interface is semantic and backend-agnostic: callers see one verifier entrypoint, one fixed calldata encoding, and one public-blame routing surface regardless of whether the proving backend is SP1 + Groth16 (primary) or a Rust-in-zkVM wrap (fallback).

## Scope and non-goals

- Freeze the Solidity-facing verifier signature as `function verify(bytes calldata proof, bytes calldata publicInputs) external view returns (bool)`.
- Freeze the calldata contract so upstream Rust adapters and downstream Foundry integration target one stable ABI under `contracts/src/`.
- Freeze failure-attribution routing as an event schema owned by a non-view router / coordinator contract, not by the pure verifier call itself.
- Keep backend internals behind an off-chain prover adapter selected by Rust feature flag.

Non-goals:

- This spec does not freeze a concrete proving system ABI such as Groth16 limbs, SP1 internal receipts, or any surrogate verifier internals.
- This spec does not require a primary path that depends on any new EIP precompile.
- This spec does not define stateful replay protection logic; replay / blame coordination belongs to a caller contract that wraps the frozen verifier interface.

## Canonical Solidity interface

The frozen verifier surface is exactly:

```solidity
interface IPvthfheP3Verifier {
    function verify(bytes calldata proof, bytes calldata publicInputs)
        external
        view
        returns (bool);
}
```

Semantics:

- `proof` is an opaque backend-defined byte string, with current design target `<= 14 KB`.
- `publicInputs` is a canonical fixed-width 200-byte blob, not an ABI tuple and not a backend-specific array of field elements.
- `verify` returns `true` iff the proof validates against the exact `publicInputs` bytes under the selected backend adapter.
- `verify` returns `false` on cryptographic failure or malformed proof/public input data that the backend chooses to treat as a soft reject.
- Because the interface is `view`, the verifier itself MUST NOT be the component that emits blame/failure events. Any public attribution event is emitted by a stateful router/coordinator that calls or interprets this verifier result.

## Calldata layout

The ABI is intentionally narrow so all P3 stacks share one calldata contract:

```text
verify(
  bytes proof,
  bytes publicInputs
)
```

### `proof` envelope

`proof` is an opaque envelope whose internal bytes are backend-defined, but the outer contract is frozen:

- byte 0: `proof_version` (`0x01` for the initial frozen interface)
- byte 1: `backend_id`
  - `0x01` = SP1 + Groth16 wrap (primary)
  - `0x02` = Rust-in-zkVM + EVM wrap (fallback)
- bytes 2..n: backend payload

Envelope rules:

- The Solidity interface does not parse backend-specific fields beyond handing the full `proof` blob to the selected verifier implementation.
- Backends may change inner serialization without changing this interface so long as they preserve the outer version/backend prefix contract.
- The frozen interface does not assume pairing points, limb counts, receipt layouts, or circuit-specific witness encodings.
- The preferred primary path remains a wrapped verifier on existing BN254 precompiles; no primary dependency on a new EIP precompile is allowed.

### `publicInputs` encoding

`publicInputs` MUST be exactly 200 bytes and MUST match the frozen P2→P3 bundle encoding. The byte layout is:

| Field | Offset | Size | Notes |
| --- | ---: | ---: | --- |
| `ciphertext_hash` | 0 | 32 | SHA-256 digest |
| `plaintext_hash` | 32 | 32 | SHA-256 digest |
| `aggregate_pk_hash` | 64 | 32 | SHA-256 digest |
| `dkg_root` | 96 | 32 | inherited P4 root |
| `epoch` | 128 | 8 | big-endian `u64` |
| `participant_set_hash` | 136 | 32 | SHA-256 digest |
| `d_commitment` | 168 | 32 | terminal fold-history digest |

This yields exactly `6 × 32 + 8 = 200` bytes.

Verifier-side requirements:

- Reject any `publicInputs` blob whose length is not exactly 200 bytes.
- Interpret `epoch` only as an 8-byte big-endian unsigned integer.
- Treat all six hash fields as opaque 32-byte commitments; the verifier interface does not reinterpret them as typed Solidity arguments.
- Preserve byte-for-byte compatibility with the P2 `P3PublicInputs` serializer; no ABI re-packing into `bytes32[6]` plus `uint64` is allowed at the frozen boundary.

## Public-input binding to the P2→P3 bundle

The 200-byte blob is the machine-readable downstream bundle contract inherited from `.sisyphus/contracts/p2-to-p3-bundle.md`.

- `ciphertext_hash` binds the ordered participant ciphertext set consumed during folding.
- `plaintext_hash` binds the aggregated plaintext claimed for the decryption epoch.
- `aggregate_pk_hash` binds the aggregated BFV public key derived from the DKG session.
- `dkg_root` binds the proof to the upstream P4 session root.
- `epoch` binds the proof to one decryption epoch and is the field that routers use for replay / stale-proof blame decisions.
- `participant_set_hash` binds the ordered participant subset.
- `d_commitment` binds the terminal ordered fold history from P2.

The verifier API therefore consumes exactly the same semantic object regardless of whether the off-chain prover stack is the primary or fallback.

## Failure attribution and abort-with-public-blame routing

Because `verify(...)` is `view`, failure attribution is frozen as a companion event schema for a router/coordinator contract in front of the verifier rather than as logs emitted by the verifier itself.

Recommended router contract placement:

- `contracts/src/interfaces/` or `contracts/src/routers/` may hold the eventual caller contract.
- The verifier implementation itself should live under `contracts/src/` and export only the frozen `verify(bytes,bytes)` entrypoint.

Frozen event schema for the router:

```solidity
event VerificationMalformedCalldata(
    bytes32 indexed publicInputsHash,
    bytes32 indexed proofHash,
    bytes32 indexed routeId,
    uint8 reasonCode
);

event VerificationFailed(
    bytes32 indexed dkgRoot,
    uint64 indexed epoch,
    bytes32 indexed participantSetHash,
    bytes32 routeId,
    uint8 reasonCode,
    bytes32 publicInputsHash,
    bytes32 proofHash
);

event PublicBlameRouted(
    bytes32 indexed dkgRoot,
    uint64 indexed epoch,
    bytes32 indexed participantSetHash,
    address router,
    bytes32 blameRef,
    uint8 reasonCode
);
```

Routing semantics:

- `VerificationMalformedCalldata` is the only blame/failure event allowed when `publicInputs` is malformed, not length-200, or otherwise not safely decodable into `(dkgRoot, epoch, participantSetHash)` from the exact bytes supplied to `verify`.
- `VerificationFailed` and `PublicBlameRouted` may be emitted only after the router has successfully decoded the exact 200-byte `publicInputs` blob used for verification; routers MUST NOT populate `dkgRoot`, `epoch`, or `participantSetHash` from caller-supplied side arguments, cached metadata, or partial decoding of malformed calldata.
- `routeId` identifies the router's local failure-attribution path (for example, replay, malformed calldata, verifier false, or downstream policy abort).
- `reasonCode` is a compact machine-readable classification owned by the router, with initial reserved meanings:
  - `1` = malformed proof envelope
  - `2` = malformed publicInputs calldata
  - `3` = verifier returned false
  - `4` = epoch replay / stale submission
  - `5` = participant-set mismatch against router policy
- `publicInputsHash = keccak256(publicInputs)` and `proofHash = keccak256(proof)` allow public blame routing without re-emitting large calldata blobs.
- For `reasonCode = 2`, routers MUST emit `VerificationMalformedCalldata` and MUST NOT emit `VerificationFailed` or `PublicBlameRouted` unless a separate exact 200-byte parse later succeeds.
- `PublicBlameRouted` is emitted when the router escalates a failed verification into the system's abort-with-public-blame flow.
- The verifier contract itself remains stateless and view-only; attribution, replay tracking, and abort handling are explicitly outboard.

## Foundry project integration (`contracts/src/`)

The frozen interface is designed to fit the existing Foundry layout without introducing a generated proof-system ABI as the public contract surface.

- Canonical interface location for the real Solidity type: `contracts/src/`.
- This task publishes only a markdown ABI sketch at `.sisyphus/design/p3/iface.sol.md`; it does not add a live `.sol` file yet.
- Future implementation may place the concrete verifier in `contracts/src/` and optional router/helpers in sibling files, while preserving the single `verify(bytes,bytes)` ABI.
- Existing generated or surrogate verifiers under `contracts/src/generated/` are implementation references only and do not define this interface.

## Off-chain prover adapter and Rust feature flags

The proving backend is frozen behind a Rust adapter rather than inside the Solidity ABI.

Recommended feature flags:

- `p3-sp1-groth16` — primary adapter
- `p3-zkvm-wrap` — fallback adapter

Adapter responsibilities:

- Serialize the exact 200-byte public-input blob from the P2 `P3PublicInputs` object.
- Wrap backend-specific proof material into the frozen `proof` envelope with `proof_version` and `backend_id`.
- Route proof generation and verification to the active backend without changing the Solidity signature.
- Ensure the on-chain artifact always consumes `bytes proof, bytes publicInputs`, even if the backend internally uses field elements, receipts, or pairing inputs.

This keeps backend churn off the Solidity boundary while letting Rust choose the active prover stack by feature flag.

## Gas and size envelope

- Public inputs are fixed at 200 bytes.
- Proof target remains `<= 14 KB`.
- On-chain verifier budget remains `<= 5,000,000` gas.
- Primary design target from D.R.5 remains SP1 with Groth16 EVM wrap at roughly Groth16-class calldata/gas, while the Rust-in-zkVM wrapped path remains the delivery fallback.

These are design constraints, not claims about one specific generated verifier ABI.

## Rejection / acceptance rules

An implementation conforming to this spec MUST:

1. expose `verify(bytes calldata proof, bytes calldata publicInputs) external view returns (bool)`;
2. reject malformed `publicInputs` lengths other than 200 bytes;
3. preserve the exact P2→P3 public-input ordering and epoch endianness;
4. keep any failure-attribution event emission outside the view verifier;
5. use a hash-only malformed-calldata event path unless the exact 200-byte blob has been successfully decoded;
6. avoid baking surrogate or backend-specific ABI fields into the public interface;
7. integrate cleanly with the existing Foundry `contracts/src/` layout and Rust feature-gated adapter flow.

## VERDICT: APPROVE
