#!/usr/bin/env python3
"""Creates a stub script at the given path."""

import os
import stat
import sys


path = sys.argv[1]
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w", encoding="utf-8") as f:
    f.write("#!/usr/bin/env python3\nimport sys\nprint(\"not implemented\")\nsys.exit(2)\n")
os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
print(f"created stub: {path}")
