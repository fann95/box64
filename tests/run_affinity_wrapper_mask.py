# SPDX-License-Identifier: MIT
"""Test extracted production affinity wrappers; --baseline reverses only the upstream fix."""
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
    match = re.search(r"^(?:EXPORT )?(?:void|int) " + name + r"\([^;]*?\)\s*\{", source, re.M)
    if not match:
        raise RuntimeError(f"Missing function {name}")
    position = source.index("{", match.start()) + 1
    depth = 1
    while depth:
        depth += (source[position] == "{") - (source[position] == "}")
        position += 1
    return source[match.start():position] + "\n"


helpers = (root / "src/tools/cpumask.c").read_text()
functions = "".join(extract(helpers, name) for name in
                    ("cpumask_shiftleft", "cpumask_shiftright", "cpumask_maxcpu"))
for directory, prefix in (("wrapped", "my_"), ("wrapped32", "my32_")):
    source = (root / "src" / directory / "wrappedlibc.c").read_text()
    for suffix in ("sched_getaffinity", "sched_setaffinity"):
        wrapper = extract(source, prefix + suffix)
        if "--baseline" in sys.argv:
            wrapper = wrapper.replace("cpumask_maxcpu(mask_,", "cpumask_maxcpu(mask,")
        functions += wrapper
with tempfile.TemporaryDirectory(prefix="box64-affinity-mask-") as directory:
    temporary = Path(directory)
    (temporary / "affinity_functions.inc").write_text(functions)
    executable = temporary / "affinity-mask"
    subprocess.run(shlex.split(os.environ.get("CC", "cc")) +
                   ["-std=gnu11", "-O1", "-g", "-D_GNU_SOURCE", "-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer", "-I", directory,
                    str(root / "tests/affinity_wrapper_mask.c"), "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=10)
