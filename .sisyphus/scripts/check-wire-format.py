import re
import sys
import os

def main():
    spec_path = ".sisyphus/design/spec-keygen.md"
    if not os.path.exists(spec_path):
        print(f"FAIL: {spec_path} not found")
        sys.exit(1)

    with open(spec_path, "r", encoding="utf-8") as f:
        content = f.read()

    msgs = re.findall(r'`(KeygenMsg\d+[^`]+)`', content)
    if not msgs:
        print("FAIL: No KeygenMsg definitions found")
        sys.exit(1)

    msg_names = set(msg.split()[0].strip('{').strip() for msg in msgs)
    
    all_pass = True
    for msg_name in msg_names:
        idx = content.find(msg_name)
        if idx == -1:
            print(f"FAIL: Could not locate {msg_name} again")
            all_pass = False
            continue
            
        context = content[max(0, idx):idx+1000].lower()
        
        has_fixed = "fixed size" in context or "fixed total byte size" in context
        has_prefixed = "length-prefixed" in context or "length prefix" in context
        
        if has_fixed or has_prefixed:
            print(f"PASS: {msg_name} has valid fixed or length-prefixed wire format documentation")
        else:
            print(f"FAIL: {msg_name} lacks valid fixed or length-prefixed wire format documentation")
            all_pass = False

    if all_pass:
        print("PASS: All message types have correct wire format documentation.")
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
