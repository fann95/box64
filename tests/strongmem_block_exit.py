# SPDX-License-Identifier: MIT
"""Check ARM64 barriers when guest stores fall through into an existing block."""
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile


def make_guest(path, store_kind="scalar"):
    # A small x86-64 ELF avoids needing an x86 cross compiler. Code is RX;
    # the stores target a separate RW page so they do not invalidate the code.
    base = 0x400200
    code, labels, relocations = bytearray(), {}, []

    def emit(hex_bytes):
        code.extend(bytes.fromhex(hex_bytes))

    def label(name):
        labels[name] = len(code)

    def branch(opcode, target):
        emit(opcode)
        relocations.append((len(code), target))
        code.extend(bytes(4))

    def store(displacement, value):
        if store_kind == "scalar":
            emit("c7 47")
            code.append(displacement)
            code.extend(struct.pack("<I", value))
        else:
            # MOVUPS xmm0 / VMOVUPS ymm0, [rdi + disp8].
            emit("0f 11 47" if store_kind == "sse" else "c5 fc 11 47")
            code.append(displacement)

    emit("48 8d 3d")  # lea data(%rip), %rdi
    offset = len(code)
    code.extend(struct.pack("<i", 0x402000 - (base + offset + 4)))
    emit("31 f6")  # xor %esi, %esi
    # Compile both RET targets before entering the store sequences.
    for target in ("g", "h", "f1", "f2"):
        branch("e8", target)
    emit("b8 3c 00 00 00 31 ff 0f 05")  # exit(0)
    label("f1")
    store(0, 1)
    store(32, 2)
    store(64, 3)
    label("g")
    emit("c3")
    label("f2")
    store(0, 4)
    emit("83 fe 01")  # cmp $1, %esi
    branch("0f 84", "out")  # je out (not taken)
    store(64, 5)
    label("h")
    emit("c3")
    label("out")
    emit("c3")
    for offset, target in relocations:
        struct.pack_into("<i", code, offset, labels[target] - offset - 4)

    elf = bytearray(4096)
    elf[:64] = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9),
                           2, 62, 1, base, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    elf[64:120] = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 4096, 4096, 4096)
    elf[120:176] = struct.pack("<IIQQQQQQ", 1, 6, 4096, 0x402000, 0x402000, 0, 4096, 4096)
    elf[512:512 + len(code)] = code
    path.write_bytes(elf)
    path.chmod(0o700)
    return {name: base + offset for name, offset in labels.items()}


def check_block(output, address, displacement, enabled, store_kind="scalar"):
    blocks = output.split("---- END OF BLOCK ----")
    blocks = [block for block in blocks if f"Stopping block {address:#x} " in block]
    assert len(blocks) == 1, f"expected one fall-through block at {address:#x}"
    block = blocks[0]
    instruction = {
        "scalar": r"ST(?:U)?R w\w+",
        "sse": r"ST(?:U)?R Q\d+",
        "avx": r"STP Q\d+, Q\d+",
    }[store_kind]
    stores = list(re.finditer(r"\b" + instruction + r", \[xRDI, " + displacement + r"\]", block))
    assert stores, f"missing final guest store at {address:#x}"
    tail = block[stores[-1].end():]
    barrier = bool(re.search(r"\bDMB ISH(?:ST)?\s", tail))
    assert barrier == enabled, f"{address:#x}: final write barrier={barrier}, expected={enabled}"


def main():
    binary = Path(sys.argv[1] if len(sys.argv) > 1 else "build/box64").resolve()
    failures = 0
    with tempfile.TemporaryDirectory(prefix="box64-strongmem-") as directory:
        guest = Path(directory) / "stores"
        for store_kind in ("scalar", "sse", "avx"):
            addresses = make_guest(guest, store_kind)
            for level in (0, 1, 2, 3):
                for weakbarrier in (0, 1, 2):
                    env = {key: value for key, value in os.environ.items() if not key.startswith("BOX64_")}
                    env.update(BOX64_NORCFILES="1", BOX64_LOG="0", BOX64_DYNACACHE="0", BOX64_DYNAREC_DUMP="1",
                               BOX64_DYNAREC_LOG="1", BOX64_DYNAREC_BIGBLOCK="1",
                               BOX64_DYNAREC_NOHOSTEXT="uscat", BOX64_DYNAREC_STRONGMEM=str(level),
                               BOX64_DYNAREC_WEAKBARRIER=str(weakbarrier))
                    result = subprocess.run([str(binary), str(guest)], env=env, text=True,
                                            capture_output=True, timeout=15)
                    try:
                        assert result.returncode == 0, f"guest exit {result.returncode}"
                        output = result.stdout + result.stderr
                        enabled = level >= (1 if store_kind == "scalar" else 2)
                        check_block(output, addresses["f1"], "0x40", enabled, store_kind)
                        check_block(output, addresses["f2"], "0x40", enabled, store_kind)
                    except AssertionError as error:
                        print(f"FAIL: {store_kind}, STRONGMEM={level}, WEAKBARRIER={weakbarrier}: {error}")
                        failures += 1
                    else:
                        print(f"PASS: {store_kind}, STRONGMEM={level}, WEAKBARRIER={weakbarrier}")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
