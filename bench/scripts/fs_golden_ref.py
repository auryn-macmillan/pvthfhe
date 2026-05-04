#!/usr/bin/env python3
"""
fs_golden_ref.py — Reference implementation of the pvthfhe-nizk Fiat-Shamir
transcript for cross-checking the Rust implementation's golden vector test.

Wire format mirrors fiat_shamir.rs:
  new(session_id, participant_id):
      hash <- SHA256(domain_sep_prefix + session_id + "/" + str(participant_id))
  absorb(label, data):
      hash.update(u64_be(len(label)) + label + u64_be(len(data)) + data)
  challenge_bytes(label, n):
      hash.update(u64_be(len(label)) + label)
      state = hash.copy().digest()
      output = b""
      counter = 0
      while len(output) < n:
          block = SHA256(u64_be(counter) + state)
          output += block
          counter += 1
      return output[:n]

Run: python3 bench/scripts/fs_golden_ref.py
"""

import hashlib
import struct


DOMAIN_SEP_PREFIX = "pvthfhe/cyclo-ajtai-d2/v1/"


def u64be(n: int) -> bytes:
    return struct.pack(">Q", n)


class Transcript:
    def __init__(self, session_id: bytes, participant_id: int) -> None:
        self._h = hashlib.sha256()
        domain = (DOMAIN_SEP_PREFIX + session_id.decode() + "/" + str(participant_id)).encode()
        self._h.update(domain)

    def absorb(self, label: bytes, data: bytes) -> None:
        self._h.update(u64be(len(label)))
        self._h.update(label)
        self._h.update(u64be(len(data)))
        self._h.update(data)

    def challenge_bytes(self, label: bytes, n: int) -> bytes:
        self._h.update(u64be(len(label)))
        self._h.update(label)
        state = self._h.copy().digest()
        out = b""
        counter = 0
        while len(out) < n:
            h = hashlib.sha256()
            h.update(u64be(counter))
            h.update(state)
            out += h.digest()
            counter += 1
        return out[:n]


def main() -> None:
    t = Transcript(b"golden", 42)
    t.absorb(b"field", b"test_vector")
    result = t.challenge_bytes(b"squeeze", 32)
    print(result.hex())


if __name__ == "__main__":
    main()
