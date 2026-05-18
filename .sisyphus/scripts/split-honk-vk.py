#!/usr/bin/env python3
"""Split HonkVerifier VK struct literal into sequential assignments."""

import re, sys

def process(in_path, out_path):
    with open(in_path) as f:
        text = f.read()

    # Find the struct literal
    start = text.find("Honk.VerificationKey({")
    if start < 0:
        sys.exit("ERROR: struct start not found")
    end = text.find("});\n        return vk;", start)
    if end < 0:
        sys.exit("ERROR: struct end not found")

    # Parse fields between { and }
    body = text[start + len("Honk.VerificationKey({"):end]
    fields = []
    depth = 0
    cur = ""
    for ch in body:
        if ch == '{': depth += 1; cur += ch
        elif ch == '}': depth -= 1; cur += ch
        elif ch == ',' and depth == 0: fields.append(cur.strip()); cur = ""
        else: cur += ch
    if cur.strip(): fields.append(cur.strip())

    # Build assignments
    g1_re = re.compile(
        r'(\w+)\s*:\s*Honk\.G1Point\(\{\s*'
        r'x:\s*uint256\((0x[0-9a-fA-F]+)\),\s*'
        r'y:\s*uint256\((0x[0-9a-fA-F]+)\)\s*\}\)'
    )
    scalar_re = re.compile(r'(circuitSize|logCircuitSize|publicInputsSize)\s*:\s*uint256\((\d+)\)')
    assignments = []
    for field in fields:
        m = scalar_re.match(field)
        if m:
            assignments.append(f"        vk.{m.group(1)} = uint256({m.group(2)});")
            continue
        m = g1_re.match(field)
        if m:
            assignments.append(
                f"        vk.{m.group(1)} = Honk.G1Point("
                f"uint256({m.group(2)}), uint256({m.group(3)}));"
            )

    # Find the declaration line
    decl = text.rfind("Honk.VerificationKey memory vk =", 0, start)
    if decl < 0: decl = start

    # Cut at the end of the HonkVerificationKey library.
    # The library closes with "}\n}" then the second pragma solidity follows.
    # Find the first occurrence of "pragma solidity" after the function.
    after_end = text[end + len("});\n        return vk;")]
    second_pragma = text.find("pragma solidity", end + len("});"))
    if second_pragma < 0:
        sys.exit("ERROR: second pragma not found")
    # The library close is just before the second pragma.
    # Find the '}' that ends the library, right before the pragma.
    lib_close = text.rfind("}", end, second_pragma)
    if lib_close < 0:
        sys.exit("ERROR: library close not found")
    lib_end = lib_close + 1  # after the closing brace

    result = (
        text[:decl]
        + "        Honk.VerificationKey memory vk;\n"
        + "\n".join(assignments)
        + "\n        return vk;\n    }\n}"
        + text[lib_end:]
    )

    with open(out_path, 'w') as f:
        f.write(result)

    g1_count = sum(1 for a in assignments if 'G1Point' in a)
    print(f"Split {len(assignments)} fields ({g1_count} G1 pts) → {out_path}")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(f"Usage: {sys.argv[0]} <in.sol> <out.sol>")
    process(sys.argv[1], sys.argv[2])
