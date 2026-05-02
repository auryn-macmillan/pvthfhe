import os
import sys

def check_file():
    path = ".sisyphus/design/selection-memo.md"
    if not os.path.exists(path):
        print(f"FAIL: {path} not found.")
        sys.exit(1)
        
    with open(path, "r") as f:
        content = f.read()
        
    checks = {
        "Decision section": "Decision",
        "Scoring Rubric section": "Scoring Rubric",
        "Rationale section": "Rationale",
        "Fallback Plan section": "Fallback Plan",
        "Open Problems section": "Open Problems",
        "Phase 2 Work Breakdown section": "Phase 2 Work Breakdown",
    }
    
    all_pass = True
    
    for check_name, keyword in checks.items():
        if keyword in content:
            print(f"PASS: {check_name} found.")
        else:
            print(f"FAIL: {check_name} not found.")
            all_pass = False
            
    if "arch-B" in content or "Architecture B" in content:
        print("PASS: Architecture B selected in Decision.")
    else:
        print("FAIL: Architecture B not selected in Decision.")
        all_pass = False
        
    if all_pass:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    check_file()
