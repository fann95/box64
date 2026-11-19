# SPDX-License-Identifier: MIT
"""Exercise actual allocator/guard/protection code; --baseline restores shared state."""
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


def extract(name):
    match = re.search(r"^(?:static )?(?:void\*|void|int) " + name + r"\([^;]*?\)\s*\{", source, re.M)
    if not match:
        raise RuntimeError(f"Function not found: {name}")
    start = source.index("{", match.start())
    depth, end = 1, start + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


declarations = "\n".join(line for line in source.splitlines() if
    re.match(r"static .*\b(setting_prot|defered_prot_p|defered_prot_sz|defered_prot_prot|defered_prot_flags)\b.*=", line))
if "--baseline" in sys.argv:
    declarations = re.sub(r"\b(?:__thread|_Thread_local)\s+", "", declarations)
macros = ""
for name in ("LOCK_PROT", "UNLOCK_PROT"):
    match = re.search(r"^#define " + name + r"\(\).*?(?=\n\n)", source, re.M | re.S)
    if not match:
        raise RuntimeError(f"Macro not found: {name}")
    macros += match.group() + "\n"
functions = "".join(extract(name) for name in
                    ("LockDynablockMemory", "UnlockDynablockMemory", "setProtection_generic", "setProtection", "map64_customMalloc"))
with tempfile.TemporaryDirectory(prefix="box64-deferred-protection-") as directory:
    temporary = Path(directory)
    (temporary / "deferred_protection_production.inc").write_text(declarations + "\n" + macros + functions)
    executable = temporary / "deferred-protection"
    subprocess.run(shlex.split(os.environ.get("CC", "cc")) +
                   ["-std=gnu11", "-O1", "-g", "-D_GNU_SOURCE", "-pthread", "-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer", "-I", directory,
                    str(root / "tests/protection_deferred_threads.c"), "-o", str(executable)], check=True)
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = environment.get("ASAN_OPTIONS", "") + ":detect_leaks=0"
    subprocess.run([str(executable)], check=True, timeout=10, env=environment)
