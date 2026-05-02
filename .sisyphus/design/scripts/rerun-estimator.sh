#!/usr/bin/env bash
set -euo pipefail

source /home/dev/.cargo/env
export PATH="/home/dev/.cargo/bin:/home/dev/.foundry/bin:/home/dev/.nargo/bin:/home/dev/.bb:$PATH"

mkdir -p .sisyphus/design

log_file=".sisyphus/design/estimator-baseline.log"

{
  echo "[task-20] rerun-estimator.sh"
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if pip3 install lattice-estimator 2>/dev/null; then
    echo "pip_install=ok:pip3"
  elif pip install lattice-estimator 2>/dev/null; then
    echo "pip_install=ok:pip"
  else
    echo "pip_install=unavailable"
  fi

  python3 - <<'PY'
import math

qis = [288230376173076481, 288230376167047169, 288230376161280001]
Q = 1
for q in qis:
    Q *= q

print(f"qis={qis}")
print(f"q_mod_16384={[q % 16384 for q in qis]}")
print(f"log2Q={math.log2(Q)}")
print(f"share_size_bytes_packed={8192 * 174 // 8}")
print(f"ciphertext_size_bytes_packed={2 * 8192 * 174 // 8}")

try:
    from estimator import *
    params = LWE.Parameters(n=8192, q=Q, Xs=ND.UniformMod(3), Xe=ND.DiscreteGaussian(3.19))
    print("estimator_status=available")
    print(LWE.estimate(params))
except Exception as exc:
    print("estimator_status=manual")
    print(f"estimator_error={exc!r}")
    print("manual_security_baseline=inherit Enclave secure BFV preset at N=8192, L=3, log2(Q)~174, target >=128 classical and >=128 PQ")
PY
} | tee "$log_file"
