# SPDX-License-Identifier: MIT
"""Exercise the actual cache loader and allocator under ASan/UBSan."""
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


def extract(source, name):
    match = re.search(r"^(?:static )?(?:void\*|size_t|int) " + name + r"\([^;]*?\)\s*\{", source, re.M)
    if not match:
        raise RuntimeError(f"Function not found: {name}")
    start = source.index("{", match.start())
    depth, end = 1, start + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


source = (root / "src/custommem.c").read_text()
if "--baseline" in sys.argv:
    source = subprocess.check_output(["git", "show", "HEAD:src/custommem.c"], cwd=root, text=True)
functions = "".join(extract(source, name) for name in
                    ("allocBlock", "freeBlock", "MmaplistAddBlock_internal"))
with tempfile.TemporaryDirectory(prefix="box64-dynacache-reclaim-") as directory:
    temporary = Path(directory)
    (temporary / "dynacache_reclaim_functions.inc").write_text(functions)
    executable = temporary / "dynacache-reclaim"
    subprocess.run(shlex.split(os.environ.get("CC", "cc")) +
                   (["-DRECLAIM_BASELINE"] if "--baseline" in sys.argv else []) +
                   ["-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer", "-I", directory, "-I", str(root / "src/dynarec"),
                    str(root / "tests/dynacache_reclaim.c"), "-o", str(executable)], check=True)
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = environment.get("ASAN_OPTIONS", "") + ":detect_leaks=0"
    subprocess.run([str(executable)], check=True, timeout=15, env=environment)
