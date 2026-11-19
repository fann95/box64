# SPDX-License-Identifier: MIT
"""Compile the actual local-scope functions with a native lifetime test harness."""
from pathlib import Path
import os
import re
import resource
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
source = (root / "src/librarian/librarian.c").read_text()


def extract(name):
    match = re.search(r"^(?:static )?(?:void|int) " + name + r"\([^;]*?\)\s*\{", source, re.M)
    if not match:
        raise RuntimeError(f"Function missing: {name}")
    start = source.index("{", match.start())
    depth, end = 1, start + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


functions = "".join(extract(name) for name in (
    "libraryInMapLib", "MapLibAddLib", "MapLibAddMapLib", "MapLibRemoveLib",
    "DetachLibraryMaplib", "MapLibRemoveMapLib", "promoteLocalLibGlobal"))
with tempfile.TemporaryDirectory(prefix="box64-maplib-lifetime-") as directory:
    temporary = Path(directory)
    (temporary / "maplib_scope_functions.inc").write_text(functions)
    executable = temporary / "maplib-scope-lifetime"
    subprocess.run(shlex.split(os.environ.get("CC", "cc")) +
                   ["-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer", "-I", directory,
                    str(root / "tests/maplib_scope_lifetime.c"), "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=10)
