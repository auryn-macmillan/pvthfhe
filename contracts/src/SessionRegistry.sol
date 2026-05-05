// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SessionRegistry
/// @notice Stores per-session DKG parameters and enforces t > n/2 and epoch replay protection.
contract SessionRegistry {
    struct Session {
        uint32 n;           // participant count
        uint32 t;           // threshold (must be > n/2)
        bytes32 rosterHash; // keccak256 of participant set
        bool registered;
    }

    mapping(bytes32 => Session) public sessions;                    // dkgRoot => Session
    mapping(bytes32 => mapping(uint64 => bool)) public consumed;    // dkgRoot => epoch => consumed

    event SessionRegistered(bytes32 indexed dkgRoot, uint32 n, uint32 t, bytes32 rosterHash);
    event EpochConsumed(bytes32 indexed dkgRoot, uint64 epoch);

    error WeakThreshold(uint32 t, uint32 n);
    error AlreadyRegistered(bytes32 dkgRoot);
    error SessionNotFound(bytes32 dkgRoot);
    error EpochAlreadyConsumed(bytes32 dkgRoot, uint64 epoch);
    error RosterMismatch(bytes32 expected, bytes32 actual);

    /// @notice Register a DKG session. Enforces t > n/2 (honest majority).
    /// @param dkgRoot    DKG transcript Merkle root (unique session identifier)
    /// @param n          Total participant count
    /// @param t          Threshold (must satisfy 2t > n)
    /// @param rosterHash keccak256 of the participant set
    function registerSession(bytes32 dkgRoot, uint32 n, uint32 t, bytes32 rosterHash) external {
        // enforce t > n/2 (i.e. 2*t > n)
        if (2 * uint64(t) <= uint64(n)) revert WeakThreshold(t, n);
        if (sessions[dkgRoot].registered) revert AlreadyRegistered(dkgRoot);
        sessions[dkgRoot] = Session(n, t, rosterHash, true);
        emit SessionRegistered(dkgRoot, n, t, rosterHash);
    }

    /// @notice Mark an epoch as consumed for a given session (replay protection).
    function markEpochConsumed(bytes32 dkgRoot, uint64 epoch) external {
        if (!sessions[dkgRoot].registered) revert SessionNotFound(dkgRoot);
        if (consumed[dkgRoot][epoch]) revert EpochAlreadyConsumed(dkgRoot, epoch);
        consumed[dkgRoot][epoch] = true;
        emit EpochConsumed(dkgRoot, epoch);
    }

    /// @notice View-only check: reverts if session is invalid, epoch consumed, or roster mismatches.
    function verifySession(bytes32 dkgRoot, uint64 epoch, bytes32 rosterHash) external view {
        Session storage s = sessions[dkgRoot];
        if (!s.registered) revert SessionNotFound(dkgRoot);
        if (consumed[dkgRoot][epoch]) revert EpochAlreadyConsumed(dkgRoot, epoch);
        if (s.rosterHash != rosterHash) revert RosterMismatch(s.rosterHash, rosterHash);
    }
}
