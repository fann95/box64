# SPDX-License-Identifier: MIT
"""Compile the current production lock paths into a deterministic race harness."""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]


def extract(source, name):
    match = re.search(r"^(?:static )?(?:void|int) " + name + r"\([^;]*?\)\s*\{", source, re.M)
    if not match:
        raise RuntimeError(f"Function not found: {name}")
    start = source.index("{", match.start())
    depth = 1
    end = start + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


with tempfile.TemporaryDirectory(prefix="box64-protection-lock-") as directory:
    temporary = Path(directory)
    custommem = (root / "src/custommem.c").read_text()
    dynablock = (root / "src/dynarec/dynablock.c").read_text()
    has_memory_guard = "int LockDynablockMemory(void)" in custommem
    functions = ""
    if has_memory_guard:
        functions += "".join(extract(custommem, name) for name in
                             ("LockDynablockMemory", "UnlockDynablockMemory"))
    functions += "".join(extract(dynablock, name) for name in
                         ("FreeDynablock", "IntervalIntersects", "FreeRangeDynablock"))
    # The optional helper lets this regression test also exercise the old source.
    if "static int cleanDBFromAddressRange_internal(" in custommem:
        functions += extract(custommem, "cleanDBFromAddressRange_internal")
    functions += "".join(extract(custommem, name) for name in
                         ("cleanDBFromAddressRange", "protectDB", "updateProtection"))
    (temporary / "protection_functions.inc").write_text(functions)
    header = (root / "src/include/custommem.h").read_text()
    (temporary / "protection_flags.inc").write_text("\n".join(
        line for line in header.splitlines() if line.startswith("#define PROT_")))
    executable = temporary / "protection-lock-order"
    guard_flags = ["-DHAVE_DYNABLOCK_MEMORY_GUARD"] if has_memory_guard else []
    subprocess.run(shlex.split(os.environ.get("CC", "cc")) + guard_flags +
                   ["-O1", "-g", "-D_GNU_SOURCE", "-pthread", "-I", directory,
                    str(root / "tests/protection_lock_order.c"), "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=10)
