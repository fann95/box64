# SPDX-License-Identifier: MIT
"""Exercise production marking, allocation scan and retirement with forced races."""
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
    match = re.search(r"^(?:static )?(?:void|int|size_t|dynablock_t\*) " + name + r"\([^;]*?\)\s*\{", source, re.M)
    if not match:
        raise RuntimeError(f"Function not found: {name}")
    start = source.index("{", match.start())
    depth, end = 1, start + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


with tempfile.TemporaryDirectory(prefix="box64-lost-block-") as directory:
    temporary = Path(directory)
    custommem = (root / "src/custommem.c").read_text()
    dynablock = (root / "src/dynarec/dynablock.c").read_text()
    free_source = dynablock
    if "--queue-baseline" in sys.argv:
        free_source = subprocess.check_output(
            ["git", "show", "HEAD:src/dynarec/dynablock.c"], cwd=root, text=True)
    functions = "".join(extract(custommem, name) for name in
                        ("LockDynablockMemory", "UnlockDynablockMemory",
                         "FindDynablockFromNativeAddress", "IsDynablockLive", "FreeDynarecMap"))
    functions += extract(custommem, "freeBlock").replace("static size_t freeBlock(", "static size_t actual_freeBlock(", 1)
    functions += "".join(extract(free_source if name in ("FreeInvalidDynablock", "FreeDynablock") else dynablock, name) for name in
                        ("RetireOrphanDynablocks", "QueueOrphanDynablock", "QueueZombieDynablock",
                         "DeferFreeDynablockMap", "DeferFreeDynablockClearRange",
                         "InvalidDynablock", "FreeInvalidDynablock", "FreeDynablock"))
    functions += "".join(extract(custommem, name) for name in
                         ("DeferLostDynablock", "RetireLostDynablocks"))
    # Use the loader's actual normalization branch, not a duplicated implementation.
    start = custommem.index("            if (bl->retire_lost) {")
    brace = custommem.index("{", start)
    depth, end = 1, brace + 1
    while depth:
        depth += (custommem[end] == "{") - (custommem[end] == "}")
        end += 1
    functions += ("static void normalize_loaded_retirement(dynablock_t* bl) {\n" +
                  custommem[start:end] + "\n}\n")
    mark_source = dynablock
    if "--baseline" in sys.argv:
        mark_source = subprocess.check_output(
            ["git", "show", "HEAD:src/dynarec/dynablock.c"], cwd=root, text=True)
    functions += extract(mark_source, "MarkDynablock")
    functions += extract(dynablock, "FlushZombieDynablocks")
    removal_function = extract(custommem, "DelMmaplist")
    if "--unmap-baseline" in sys.argv:
        # Restore the old header-omitting range while retaining the lock fix,
        # isolating that UAF from the independent concurrent-unmapping defect.
        removal_function = removal_function.replace(
            "rb_unset(rbt_dynmem, (uintptr_t)addr, (uintptr_t)addr + size);",
            "rb_unset(rbt_dynmem, (uintptr_t)list->chunks[i]->block, "
            "(uintptr_t)list->chunks[i]->block+list->chunks[i]->size);")
    functions += removal_function
    (temporary / "lost_functions.inc").write_text(functions)
    executable = temporary / "lost-retirement"
    subprocess.run(shlex.split(os.environ.get("CC", "cc")) +
                   (["-DONLY_DUPLICATE"] if "--queue-baseline" in sys.argv else []) +
                   ["-O1", "-g", "-D_GNU_SOURCE", "-pthread", "-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer", "-I", directory, "-I", str(root / "src/dynarec"),
                    str(root / "tests/lost_dynablock_retirement.c"), "-o", str(executable)], check=True)
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = environment.get("ASAN_OPTIONS", "") + ":detect_leaks=0"
    subprocess.run([str(executable)], check=True, timeout=15, env=environment)
