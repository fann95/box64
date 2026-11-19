# SPDX-License-Identifier: MIT
"""Exercise the production reference update with three- and four-level tables."""
from pathlib import Path
import os
import re
import resource
import shlex
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
source = (root / "src/custommem.c").read_text()
if "--baseline" in sys.argv:
    source = subprocess.check_output(
        ["git", "show", "HEAD:src/custommem.c"], cwd=root, text=True)
match = re.search(r"^int setJumpTableIfRef64\([^;]*?\)\s*\{", source, re.M)
start = source.index("{", match.start())
depth, end = 1, start + 1
while depth:
    depth += (source[end] == "{") - (source[end] == "}")
    end += 1
with tempfile.TemporaryDirectory(prefix="box64-jumptable-ref-") as directory:
    temporary = Path(directory)
    (temporary / "jumptable_function.inc").write_text(source[match.start():end])
    for levels in (3, 4):
        executable = temporary / f"jumptable-{levels}"
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) +
                       (["-DTEST_FOUR_LEVELS"] if levels == 4 else []) +
                       ["-O1", "-g", "-fsanitize=address,undefined", "-I", directory,
                        str(root / "tests/jumptable_missing_ref.c"), "-o", str(executable)],
                       check=True)
        environment = os.environ.copy()
        environment["ASAN_OPTIONS"] = environment.get("ASAN_OPTIONS", "") + ":detect_leaks=0"
        subprocess.run([str(executable)], check=True, timeout=10, env=environment)
