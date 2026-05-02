#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
  t11-rlwe-relation)
    cat <<'EOF'
source /home/dev/.cargo/env
export PATH="/home/dev/.cargo/bin:/home/dev/.foundry/bin:/home/dev/.nargo/bin:/home/dev/.bb:$PATH"

# Methodology: logical N -> coefficient surrogate used in Noir
# N512  -> 16 coefficients
# N2048 -> 32 coefficients
# N8192 -> 64 coefficients

cd /home/dev/pvthfhe/circuits
nargo compile --package rlwe_relation
nargo execute --package rlwe_relation --prover-name Prover_valid
bb write_vk --scheme ultra_honk -b target/rlwe_relation.json -o target
bb prove --scheme ultra_honk -b target/rlwe_relation.json -w target/rlwe_relation.gz -o target
bb verify --scheme ultra_honk -k target/vk -p target/proof -i target/public_inputs

# Repeat prove+verify 10 times per surrogate coefficient count after regenerating:
#   N512  => COEFF_COUNT=16
#   N2048 => COEFF_COUNT=32
#   N8192 => COEFF_COUNT=64
EOF
    ;;
  *)
    echo "not implemented"
    exit 2
    ;;
esac
