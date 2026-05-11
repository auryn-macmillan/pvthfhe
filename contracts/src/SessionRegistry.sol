// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";

/// @title SessionRegistry
/// @notice Stores per-session DKG parameters and enforces t > n/2 and epoch replay protection.
///         Access-controlled: SESSION_CREATOR_ROLE for register/abort, VERIFIER_ROLE for markEpochConsumed.
contract SessionRegistry is AccessControl {
    // -------------------------------------------------------------------------
    // Roles (R6.3)
    // -------------------------------------------------------------------------

    /// @notice Role allowed to call registerSession() and abortSession().
    bytes32 public constant SESSION_CREATOR_ROLE = keccak256("SESSION_CREATOR_ROLE");

    /// @notice Role allowed to call markEpochConsumed() (typically the PvtFheVerifier contract).
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    // -------------------------------------------------------------------------
    // Data structures
    // -------------------------------------------------------------------------

    struct Session {
        uint32 n;           // participant count
        uint32 t;           // threshold (must be > n/2)
        bytes32 rosterHash; // keccak256 of participant set
        bool registered;
        bool aborted;       // true when session has been explicitly aborted (liveness: allows dkgRoot reuse)
        uint64 runId;       // increments on each re-registration after abort (R6.9 / F69)
    }

    mapping(bytes32 => Session) public sessions;                                     // dkgRoot => Session
    mapping(bytes32 => mapping(uint64 => mapping(uint64 => bool))) internal _consumed; // dkgRoot => epoch => runId => consumed (R6.9)

    event SessionRegistered(bytes32 indexed dkgRoot, uint32 n, uint32 t, bytes32 rosterHash, uint64 runId);
    event EpochConsumed(bytes32 indexed dkgRoot, uint64 epoch, uint64 runId);
    event SessionAborted(bytes32 indexed dkgRoot, uint64 runId);

    error WeakThreshold(uint32 t, uint32 n);
    error AlreadyRegistered(bytes32 dkgRoot);
    error SessionNotFound(bytes32 dkgRoot);
    error SessionAbortedError(bytes32 dkgRoot);
    error EpochAlreadyConsumed(bytes32 dkgRoot, uint64 epoch);
    error RosterMismatch(bytes32 expected, bytes32 actual);

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /// @notice Sets up the registry with DEFAULT_ADMIN_ROLE for the deployer.
    ///         The deployer must then grant SESSION_CREATOR_ROLE and VERIFIER_ROLE
    ///         to the relevant actors.
    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    // -------------------------------------------------------------------------
    // Session management (SESSION_CREATOR_ROLE)
    // -------------------------------------------------------------------------

    /// @notice Register a DKG session. Enforces t > n/2 (honest majority).
    /// @dev    An aborted session may be re-registered (enables DKG restart with same committee).
    ///         Requires SESSION_CREATOR_ROLE.
    /// @param dkgRoot    DKG transcript Merkle root (unique session identifier)
    /// @param n          Total participant count
    /// @param t          Threshold (must satisfy 2t > n)
    /// @param rosterHash keccak256 of the participant set
    function registerSession(bytes32 dkgRoot, uint32 n, uint32 t, bytes32 rosterHash)
        external
        onlyRole(SESSION_CREATOR_ROLE)
    {
        // enforce t > n/2 (i.e. 2*t > n)
        if (2 * uint64(t) <= uint64(n)) revert WeakThreshold(t, n);
        Session storage existing = sessions[dkgRoot];
        if (existing.registered && !existing.aborted) revert AlreadyRegistered(dkgRoot);
        // R6.9: increment runId on restart (0 for first registration)
        uint64 newRunId = existing.registered ? existing.runId + 1 : 0;
        sessions[dkgRoot] = Session(n, t, rosterHash, true, false, newRunId);
        emit SessionRegistered(dkgRoot, n, t, rosterHash, newRunId);
    }

    /// @notice Abort a registered session, allowing it to be re-registered.
    /// @dev    Liveness mechanism: if off-chain DKG stalls, abort clears the lock so the
    ///         same committee (same dkgRoot) can restart without deploying a new contract.
    ///         Any epochs already consumed remain consumed to prevent replay across retries.
    ///         Requires SESSION_CREATOR_ROLE.
    function abortSession(bytes32 dkgRoot)
        external
        onlyRole(SESSION_CREATOR_ROLE)
    {
        Session storage s = sessions[dkgRoot];
        if (!s.registered) revert SessionNotFound(dkgRoot);
        if (s.aborted) revert SessionAbortedError(dkgRoot);
        s.aborted = true;
        emit SessionAborted(dkgRoot, s.runId);
    }

    // -------------------------------------------------------------------------
    // Epoch consumption (VERIFIER_ROLE)
    // -------------------------------------------------------------------------

    /// @notice Mark an epoch as consumed for a given session (replay protection).
    ///         R6.9: consumption is scoped to the session's current runId,
    ///         so abort+restart does NOT block the new run from reusing epochs.
    ///         Requires VERIFIER_ROLE (typically granted to PvtFheVerifier).
    function markEpochConsumed(bytes32 dkgRoot, uint64 epoch)
        external
        onlyRole(VERIFIER_ROLE)
    {
        Session storage s = sessions[dkgRoot];
        if (!s.registered) revert SessionNotFound(dkgRoot);
        if (s.aborted) revert SessionAbortedError(dkgRoot);
        if (_consumed[dkgRoot][epoch][s.runId]) revert EpochAlreadyConsumed(dkgRoot, epoch);
        _consumed[dkgRoot][epoch][s.runId] = true;
        emit EpochConsumed(dkgRoot, epoch, s.runId);
    }

    /// @notice Check whether an epoch is consumed for the session's current runId.
    ///         Reverts if session is not found or aborted.
    function isEpochConsumed(bytes32 dkgRoot, uint64 epoch) external view returns (bool) {
        Session storage s = sessions[dkgRoot];
        if (!s.registered) revert SessionNotFound(dkgRoot);
        if (s.aborted) revert SessionAbortedError(dkgRoot);
        return _consumed[dkgRoot][epoch][s.runId];
    }

    /// @notice Low-level consumed check for a specific (dkgRoot, epoch, runId).
    ///         Used by tests and off-chain indexers to inspect historical consumed state.
    function consumed(bytes32 dkgRoot, uint64 epoch, uint64 runId) external view returns (bool) {
        return _consumed[dkgRoot][epoch][runId];
    }

    /// @notice Returns the current runId for a session. Reverts if not registered.
    function getRunId(bytes32 dkgRoot) external view returns (uint64) {
        Session storage s = sessions[dkgRoot];
        if (!s.registered) revert SessionNotFound(dkgRoot);
        return s.runId;
    }

    /// @notice View-only check: reverts if session is invalid, epoch consumed (current runId), or roster mismatches.
    function verifySession(bytes32 dkgRoot, uint64 epoch, bytes32 rosterHash) external view {
        Session storage s = sessions[dkgRoot];
        if (!s.registered) revert SessionNotFound(dkgRoot);
        if (s.aborted) revert SessionAbortedError(dkgRoot);
        if (_consumed[dkgRoot][epoch][s.runId]) revert EpochAlreadyConsumed(dkgRoot, epoch);
        if (s.rosterHash != rosterHash) revert RosterMismatch(s.rosterHash, rosterHash);
    }
}
