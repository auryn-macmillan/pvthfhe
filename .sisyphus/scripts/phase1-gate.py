import json
import os
import sys

def check_file(path):
    exists = os.path.exists(path)
    print(f"[ARTIFACT] {path}: {'PASS' if exists else 'FAIL'}")
    return exists

def validate_cost_json(path, schema):
    if not os.path.exists(path):
        return False
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        
        required_top = schema.get("required", [])
        missing_top = [k for k in required_top if k not in data]
        
        if missing_top:
            print(f"[SCHEMA] {path}: FAIL (Missing top keys: {missing_top})")
            return False
            
        if "costs" in data and isinstance(data["costs"], list):
            item_schema = schema["properties"]["costs"]["items"]
            required_item = item_schema.get("required", [])
            for i, item in enumerate(data["costs"]):
                missing_item = [k for k in required_item if k not in item]
                if missing_item:
                    print(f"[SCHEMA] {path}: FAIL (Item {i} missing keys: {missing_item})")
                    return False
        
        print(f"[SCHEMA] {path}: PASS")
        return True
    except Exception as e:
        print(f"[SCHEMA] {path}: FAIL ({str(e)})")
        return False

def main():
    all_pass = True
    
    required_artifacts = [
        ".sisyphus/research/threat-model.md",
        ".sisyphus/research/assumptions-ledger.md",
        ".sisyphus/research/lit-survey.md",
        ".sisyphus/research/backend-selection.md",
        ".sisyphus/research/bootstrapping-pv-memo.md",
        ".sisyphus/research/arch-A-silent-setup.md",
        ".sisyphus/research/arch-A-costs.json",
        ".sisyphus/research/arch-B-lattice-folding.md",
        ".sisyphus/research/arch-B-costs.json",
        ".sisyphus/research/arch-C-noir-recursive.md",
        ".sisyphus/research/arch-C-costs.json",
        ".sisyphus/research/cost-comparison.md",
        ".sisyphus/research/cost-comparison.json",
        ".sisyphus/research/phase1-gate-report.md",
        ".sisyphus/research/phase1-gate.json",
        "bench/results/rlwe-relation-8192.json",
        "bench/results/folding-1024.json",
        "bench/results/kzg-batch-128.json"
    ]
    
    print("--- Artifact Checks ---")
    for art in required_artifacts:
        if not check_file(art):
            all_pass = False
            
    print("\n--- Schema Checks ---")
    schema_path = ".sisyphus/research/costs.schema.json"
    if os.path.exists(schema_path):
        with open(schema_path, 'r') as f:
            costs_schema = json.load(f)
        for arch in ["A", "B", "C"]:
            path = f".sisyphus/research/arch-{arch}-costs.json"
            if not validate_cost_json(path, costs_schema):
                all_pass = False
    else:
        print(f"CRITICAL: Schema file {schema_path} missing")
        all_pass = False

    print("\n--- Gate Decision Checks ---")
    gate_path = ".sisyphus/research/phase1-gate.json"
    if os.path.exists(gate_path):
        try:
            with open(gate_path, 'r') as f:
                gate = json.load(f)
            
            check_defer = gate.get("bootstrapping_pv_decision") == "defer"
            print(f"[DECISION] bootstrapping_pv_decision is 'defer': {'PASS' if check_defer else 'FAIL'}")
            
            check_go = gate.get("verdict") == "GO"
            print(f"[DECISION] verdict is 'GO': {'PASS' if check_go else 'FAIL'}")
            
            scores = gate.get("architecture_scores", {})
            viable_count = 0
            if scores.get("A", {}).get("recommendation") in ["primary", "fallback"]:
                viable_count += 1
            if scores.get("B", {}).get("recommendation") in ["primary", "fallback"]:
                viable_count += 1
            
            check_viable = viable_count >= 2
            print(f"[DECISION] Viable architectures (A+B) >= 2: {'PASS' if check_viable else 'FAIL'} (Found {viable_count})")
            
            if not (check_defer and check_go and check_viable):
                all_pass = False
        except Exception as e:
            print(f"[DECISION] Error reading gate JSON: {str(e)}")
            all_pass = False
    else:
        print(f"[DECISION] {gate_path} missing: FAIL")
        all_pass = False

    if all_pass:
        print("\nPHASE 1 GATE: PASS")
        sys.exit(0)
    else:
        print("\nPHASE 1 GATE: FAIL")
        sys.exit(1)

if __name__ == "__main__":
    main()
