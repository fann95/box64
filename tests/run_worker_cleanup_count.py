# SPDX-License-Identifier: MIT
"""Check worker lifetime through TLS cleanup; --baseline restores prior functions."""
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
source = (root / "src/libtools/threads.c").read_text()
header = (root / "src/include/threads.h").read_text()
worker_type = re.search(r"typedef struct emuthread_s \{.*?\} emuthread_t;", header, re.S).group()
if "--baseline" in sys.argv:
    source = subprocess.check_output(["git", "show", "HEAD:src/libtools/threads.c"], cwd=root, text=True)


def extract(name):
    match = re.search(r"^(?:static )?void\*? " + name + r"\([^;]*?\)\s*\{", source, re.M)
    if not match:
        raise RuntimeError(f"Function missing: {name}")
    start = source.index("{", match.start())
    depth, end = 1, start + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


functions = "".join(extract(name) for name in
                    ("emuthread_destroy", "emuthread_cancel", "thread_set_emu", "pthread_routine"))
with tempfile.TemporaryDirectory(prefix="box64-worker-cleanup-") as directory:
    temporary = Path(directory)
    (temporary / "worker_type.inc").write_text(worker_type)
    (temporary / "worker_functions.inc").write_text(functions)
    executable = temporary / "worker-cleanup"
    subprocess.run(shlex.split(os.environ.get("CC", "cc")) +
                   ["-std=gnu11", "-O1", "-g", "-D_GNU_SOURCE", "-pthread", "-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer", "-I", directory,
                    str(root / "tests/worker_cleanup_count.c"), "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=10)
