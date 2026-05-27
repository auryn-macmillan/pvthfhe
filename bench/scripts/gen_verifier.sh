#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

cd "$REPO_ROOT"
cargo run -p pvthfhe-circuit-tests --bin gen_nova_state_witness

cd "$REPO_ROOT/circuits"
nargo execute --package nova_state_commitment --prover-name Nova_state_commitment
cp target/nova_state_commitment.json nova_state_commitment/target/nova_state_commitment.json
cp target/nova_state_commitment.gz nova_state_commitment/target/nova_state_commitment.gz
bb write_vk --scheme ultra_honk -b nova_state_commitment/target/nova_state_commitment.json -o nova_state_commitment/target
if bb write_solidity_verifier --scheme ultra_honk -k nova_state_commitment/target/vk -o "$REPO_ROOT/contracts/src/generated/UltraHonkVerifier.sol"; then
  printf '%s\n' 'Generated UltraHonkVerifier.sol via bb write_solidity_verifier'
else
  printf '%s\n' 'bb write_solidity_verifier failed for the current vk shape; leaving checked-in fallback verifier in place' >&2
fi
