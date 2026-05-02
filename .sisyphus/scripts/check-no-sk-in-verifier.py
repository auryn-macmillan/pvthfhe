import sys
import re

try:
    with open(".sisyphus/design/spec-decrypt.md", "r") as f:
        content = f.read()

    match = re.search(r'## Public verifier algorithm(.*?)(?:## |$)', content, re.DOTALL)
    if not match:
        print("FAIL: Could not find 'Public verifier algorithm' section")
        sys.exit(1)

    verifier_section = match.group(1)
    matches = re.findall(r'sk_i|sk_', verifier_section)
    count = len(matches)

    if count == 0:
        print(f"PASS: {count} references to sk_i or sk_ in verifier section.")
        sys.exit(0)
    else:
        print(f"FAIL: Found {count} references to sk_i or sk_ in verifier section.")
        sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
