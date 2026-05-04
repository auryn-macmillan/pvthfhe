#!/usr/bin/env python3
"""Reference SHA-256 D2 hash-bridge for cross-checking pvthfhe-nizk."""
import hashlib, struct, sys


def commit(session_id: str, participant_id: int, secret_share: int) -> bytes:
    data = session_id.encode("utf-8")
    data += struct.pack("<H", participant_id)  # u16 LE
    data += struct.pack(">Q", secret_share)    # u64 BE
    return hashlib.sha256(data).digest()


if __name__ == "__main__":
    sid, pid, share = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    print(commit(sid, pid, share).hex())
