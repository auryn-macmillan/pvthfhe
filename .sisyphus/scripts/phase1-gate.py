#!/usr/bin/env python3
"""Phase-1 gate for pvthfhe-real-p2p3: verifies all N1-N8 deliverables."""
import subprocess, sys, os

results = []

def check(label, ok):
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {label}")
    results.append(ok)
    return ok

for path in [
    "crates/pvthfhe-nizk/src/lib.rs",
    "crates/pvthfhe-nizk/src/ajtai.rs",
    "crates/pvthfhe-nizk/src/hash_bridge.rs",
    "crates/pvthfhe-nizk/src/sigma.rs",
    "crates/pvthfhe-nizk/src/fiat_shamir.rs",
    "crates/pvthfhe-nizk/src/adapter.rs",
    "crates/pvthfhe-fhe/src/real_nizk.rs",
    "SECURITY.md",
    "docs/security-proofs/p1/theorem-inventory.md",
]:
    check(f"file exists: {path}", os.path.exists(path))

check("BACKEND_ID = cyclo-ajtai-d2-conditional",
      "cyclo-ajtai-d2-conditional" in open("crates/pvthfhe-nizk/src/lib.rs").read())

check("SECURITY.md has P1 CRITICAL banner",
      "P1 (CRITICAL)" in open("SECURITY.md").read())

check("T2 status = skeleton (reduction target: Cyclo T3 o T5)",
      "Cyclo T3" in open("docs/security-proofs/p1/theorem-inventory.md").read())

r = subprocess.run(
    ["cargo", "test", "-p", "pvthfhe-nizk", "--release"],
    capture_output=True, text=True
)
check("cargo test -p pvthfhe-nizk --release: exit 0", r.returncode == 0)
if r.returncode != 0:
    print(r.stdout[-3000:])
    print(r.stderr[-3000:])

r = subprocess.run(
    ["cargo", "test", "-p", "pvthfhe-fhe", "--features", "real-nizk"],
    capture_output=True, text=True
)
check("cargo test -p pvthfhe-fhe --features real-nizk: exit 0", r.returncode == 0)
if r.returncode != 0:
    print(r.stdout[-3000:])
    print(r.stderr[-3000:])

r = subprocess.run(
    ["cargo", "clippy", "-p", "pvthfhe-nizk", "-p", "pvthfhe-fhe",
     "--all-targets", "--", "-D", "warnings"],
    capture_output=True, text=True
)
check("cargo clippy -D warnings: exit 0", r.returncode == 0)

check("nizk_adversarial.rs exists",
      os.path.exists("crates/pvthfhe-nizk/tests/nizk_adversarial.rs"))

if all(results):
    print("\nPHASE 1 GATE: PASS")
    sys.exit(0)
else:
    print("\nPHASE 1 GATE: FAIL")
    sys.exit(1)
