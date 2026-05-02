import sys
import os

def main():
    spec_path = ".sisyphus/design/spec-keygen.md"
    if not os.path.exists(spec_path):
        print(f"FAIL: {spec_path} not found")
        sys.exit(1)

    with open(spec_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    in_table = False
    row_count = 0
    
    for line in lines:
        line = line.strip()
        if line.startswith("|") and "Failure Mode" in line and "Blame Target" in line:
            in_table = True
            continue
            
        if in_table and line.startswith("|"):
            if "---" in line:
                continue
            row_count += 1
        elif in_table and not line.startswith("|"):
            in_table = False

    if row_count >= 4:
        print(f"PASS: Blame matrix has {row_count} failure modes (>= 4 required)")
        sys.exit(0)
    else:
        print(f"FAIL: Blame matrix has {row_count} failure modes (need >= 4)")
        sys.exit(1)

if __name__ == "__main__":
    main()
