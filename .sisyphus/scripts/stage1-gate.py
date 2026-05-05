#!/usr/bin/env python3
"""Stage 1 gate for pvthfhe redteam: verifies all H1-H8 remediation deliverables."""
import subprocess, sys, os, re

results = []

def check(label, ok):
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {label}")
    results.append(ok)
    return ok

# 1. T13 all-approved: evidence files for t11.5, t11.6, t11.7, t11.8 exist
for path in [
    ".sisyphus/evidence/t11.5-side-channel-audit.md",
    ".sisyphus/evidence/t11.6-withholding-griefing.md",
    ".sisyphus/evidence/t11.7-liveness.md",
    ".sisyphus/evidence/t11.8-adversary-model.md",
]:
    check(f"T13 evidence exists: {path}", os.path.exists(path))

# 2. T15 published: interfold threat model exists and is non-empty
path = "docs/interfold-threat-model.md"
check(f"T15 threat model exists and non-empty: {path}",
      os.path.exists(path) and os.path.getsize(path) > 0)

# 3. Stage 0 T2 tripwire: build.rs still emits SURROGATE ACTIVE warning
build_rs = "crates/pvthfhe-fhe/build.rs"
check("Stage 0 T2 tripwire: build.rs contains 'SURROGATE ACTIVE'",
      os.path.exists(build_rs) and "SURROGATE ACTIVE" in open(build_rs).read())

# 4. Stage 0 T3 mock policy: PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK required
# May live in lib.rs or mock.rs
mock_opt_in = "PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK"
candidates = [
    "crates/pvthfhe-fhe/src/lib.rs",
    "crates/pvthfhe-fhe/src/mock.rs",
    "crates/pvthfhe-fhe/src/fhers.rs",
]
found_mock_optin = any(
    os.path.exists(p) and mock_opt_in in open(p).read()
    for p in candidates
)
check("Stage 0 T3 mock opt-in: source references PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK",
      found_mock_optin)

# 5. Finding-disposition-matrix exists and contains H1 through H8
matrix = ".sisyphus/evidence/finding-disposition-matrix.md"
if os.path.exists(matrix):
    content = open(matrix).read()
    all_present = all(f"| H{i}" in content for i in range(1, 9))
    check("Finding-disposition-matrix contains H1–H8 entries", all_present)
else:
    check("Finding-disposition-matrix exists", False)

# 6. No deployment-relevant Deferred Highs without Accepted-Risk or Fixed marker
if os.path.exists(matrix):
    content = open(matrix).read()
    bad_rows = []
    for line in content.splitlines():
        m = re.match(r'\|\s*(H[1-8])\s*\|', line)
        if m:
            if "Deferred" in line and "Accepted-Risk" not in line and "Fixed" not in line:
                bad_rows.append(line.strip())
    check("No deployment-relevant Deferred Highs without disposition",
          len(bad_rows) == 0)
    if bad_rows:
        for row in bad_rows:
            print(f"  BAD ROW: {row}")
else:
    check("Matrix file present for deferred-check", False)

# 7. forge tests pass
r = subprocess.run(
    ["forge", "test", "--root", "contracts"],
    capture_output=True, text=True
)
check("forge test --root contracts: exit 0", r.returncode == 0)
if r.returncode != 0:
    print(r.stdout[-3000:])
    print(r.stderr[-3000:])

# 8. cargo build for pvthfhe-nizk and pvthfhe-fhe
r = subprocess.run(
    ["cargo", "build", "-p", "pvthfhe-nizk", "-p", "pvthfhe-fhe"],
    capture_output=True, text=True
)
check("cargo build -p pvthfhe-nizk -p pvthfhe-fhe: exit 0", r.returncode == 0)
if r.returncode != 0:
    print(r.stdout[-3000:])
    print(r.stderr[-3000:])

# Summary
print()
if all(results):
    print("STAGE 1 GATE: PASS")
    sys.exit(0)
else:
    print("STAGE 1 GATE: FAIL")
    sys.exit(1)
