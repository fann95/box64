# SPDX-License-Identifier: MIT
"""Real guest ESP/RSP immediate ADD width regression, without an x86 sysroot.

The guest temporarily uses a register value as RSP, never dereferences it, and
restores the original stack before any syscall. An indirect branch after ADD
forces the pending-flags block-end path affected by upstream 60eac36c4d.
"""
import argparse
import os
from pathlib import Path
import resource
import struct
import subprocess
import tempfile

from thread_cleanup_dso import assemble


CASES = (
    ("esp small immediate with carry", "esp", 0x12340000FFFFFFFC, 8, 4),
    ("esp large immediate", "esp", 0x12340000FFFFF000, 0x12345, 0x11345),
    ("esp negative immediate", "esp", 0x1234000000000000, -1, 0xFFFFFFFF),
    ("rsp small immediate stays 64-bit", "rsp", 0x12340000FFFFFFFC, 8, 0x1234000100000004),
    ("rsp large immediate stays 64-bit", "rsp", 0x12340000FFFFF000, 0x12345, 0x1234000100011345),
    ("rsp negative immediate stays 64-bit", "rsp", 0x1234000000000000, -1, 0x1233FFFFFFFFFFFF),
)


def guest(directory):
    lines = ["entry:", "mov r12, rsp", "xor r13d, r13d"]
    for index, (_, register, start, value, expected) in enumerate(CASES):
        lines += [f"lea rbx, [rip+.Lafter{index}]", f"movabs rsp, {start:#x}",
                  f"add {register}, {value}", "jmp rbx", f".Lafter{index}:",
                  "mov rax, rsp", "mov rsp, r12", f"movabs rdx, {expected:#x}",
                  "cmp rax, rdx", f"je .Lok{index}", f"or r13d, {1 << index}", f".Lok{index}:"]
    lines += ["mov edi, r13d", "mov eax, 60", "syscall"]
    code, symbols = assemble(directory, "stack-add", "\n".join(lines))
    image = bytearray(0x1000)
    image.extend(code)
    base = 0x400000
    struct.pack_into("<16sHHIQQQIHHHHHH", image, 0,
                     b"\x7fELF\x02\x01\x01" + bytes(9), 2, 62, 1,
                     base + 0x1000 + symbols["entry"], 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", image, 64, 1, 5, 0, base, base,
                     len(image), len(image), 4096)
    path = directory / "stack-add"
    path.write_bytes(image)
    path.chmod(0o700)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("box64", type=Path)
    parser.add_argument("--interpreter", action="store_true")
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    environment = {**os.environ, "BOX64_NORCFILES": "1", "BOX64_LOG": "0",
                   "BOX64_SHOWSEGV": "0", "BOX64_SHOWBT": "0", "BOX64_DYNAREC_SAFEFLAGS": "0",
                   "BOX64_DYNAREC_BIGBLOCK": "0", "BOX64_DYNAREC_FORWARD": "0",
                   "BOX64_DYNAREC_NATIVEFLAGS": "0", "BOX64_DYNAREC_DF": "1",
                   "BOX64_DYNAREC": "0" if args.interpreter else "1"}
    with tempfile.TemporaryDirectory(prefix="box64-stack-add-") as temporary:
        program = guest(Path(temporary))
        run = subprocess.run([str(args.box64.resolve()), str(program)],
                             env=environment, capture_output=True, text=True, timeout=10)
    if run.returncode == 0:
        print("PASS: ESP zero-extends for small/large/negative ADD, RSP preserves 64-bit arithmetic")
    else:
        if 0 < run.returncode < 64:
            for index, (name, *_rest) in enumerate(CASES):
                if run.returncode & (1 << index):
                    print("FAIL:", name)
        else:
            print("FAIL: guest exit", run.returncode)
        print(run.stdout + run.stderr)
    return 0 if run.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
