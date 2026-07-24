#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

cd "$REPO_ROOT"
cargo run -p pvthfhe-circuit-tests --bin gen_nova_state_witness

cd "$REPO_ROOT/circuits"
nargo execute --package ivc_state_commitment --prover-name Ivc_state_commitment
cp target/ivc_state_commitment.json ivc_state_commitment/target/ivc_state_commitment.json
cp target/ivc_state_commitment.gz ivc_state_commitment/target/ivc_state_commitment.gz
bb write_vk --scheme ultra_honk -b ivc_state_commitment/target/ivc_state_commitment.json -o ivc_state_commitment/target
if bb write_solidity_verifier --scheme ultra_honk -k ivc_state_commitment/target/vk -o "$REPO_ROOT/contracts/src/generated/UltraHonkVerifier.sol"; then
  printf '%s\n' 'Generated UltraHonkVerifier.sol via bb write_solidity_verifier'
else
  printf '%s\n' 'bb write_solidity_verifier failed for the current vk shape; leaving checked-in fallback verifier in place' >&2
fi
