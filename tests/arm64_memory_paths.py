# SPDX-License-Identifier: MIT
"""Compare scalar loads, stores and locked operations across ARM64 memory paths."""
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


MASK64 = (1 << 64) - 1
SEED = 0xFEDCBA9876543210
REPLACEMENT = 0x0123456789ABCDEF


def make_guest(path, group="all"):
    code_base, data_base, output_base = 0x400000, 0x500000, 0x510000
    code = bytearray(0x200)
    data = bytearray((i * 97 + 0x5B) & 255 for i in range(0x3000))
    functions, calls, expected, names = {}, [], bytearray(), []
    operations = [
        ("u8", "0f b6 87", 1, 0), ("u16", "0f b7 87", 2, 0),
        ("u32", "8b 87", 4, 0), ("u64", "48 8b 87", 8, 0),
        ("s8x", "48 0f be 87", 1, 64), ("s8w", "0f be 87", 1, 32),
        ("s16x", "48 0f bf 87", 2, 64), ("s16w", "0f bf 87", 2, 32),
        ("s32x", "48 63 87", 4, 64),
        ("store8", "88 87", 1, 0), ("store16", "66 89 87", 2, 0),
        ("store32", "89 87", 4, 0), ("store64", "48 89 87", 8, 0),
        ("xchg16", "66 87 87", 2, 0), ("xchg32", "87 87", 4, 0),
        ("xchg64", "48 87 87", 8, 0),
        ("xadd16", "f0 66 0f c1 87", 2, 0),
        ("xadd32", "f0 0f c1 87", 4, 0),
        ("xadd64", "f0 48 0f c1 87", 8, 0),
        ("cmpxchg32", "f0 0f b1 8f", 4, 0),
        ("cmpxchg64", "f0 48 0f b1 8f", 8, 0),
    ]
    if group == "scalar":
        operations = [op for op in operations if not op[0].startswith(("xchg", "xadd", "cmpxchg"))]
    elif group != "all":
        operations = [op for op in operations if op[0] == group]
    assert operations, f"unknown operation group: {group}"
    code += b"\x49\xbe" + struct.pack("<Q", output_base)  # r14 = result buffer
    for name, instruction, size, signed in operations:
        for displacement in (-257, -256, -1, 0, 255, 256):
            function = (name, displacement)
            functions[function] = bytes.fromhex(instruction) + struct.pack("<i", displacement)
            if name.startswith("xadd"):
                functions[function] += bytes.fromhex("9c 5a 81 e2 d5 08 00 00")  # capture defined arithmetic flags
            functions[function] += b"\xc3"
            # Aligned, unaligned within 16 bytes, crossing 16/64 bytes and a page.
            for position in (0x1000, 0x1001, 0x1007, 0x100D, 0x100F, 0x103F, 0x1FFF):
                old = int.from_bytes(data[position:position + size], "little")
                mask = (1 << (8 * size)) - 1
                accumulator = old if name.startswith("cmpxchg") and position & 1 else SEED
                code += b"\x48\xbf" + struct.pack("<Q", data_base + position - displacement)
                code += b"\x48\xb8" + struct.pack("<Q", accumulator)
                code += b"\x48\xb9" + struct.pack("<Q", REPLACEMENT)
                code += b"\xe8"
                calls.append((len(code), function))
                code += bytes(4)
                code += b"\x49\x89\x86" + struct.pack("<i", len(expected))
                result, new = accumulator, old
                if name.startswith("store"):
                    new = accumulator & mask
                elif name.startswith(("xchg", "xadd")):
                    result = old if size != 2 else (accumulator & ~mask) | old
                    new = (old + accumulator if name.startswith("xadd") else accumulator) & mask
                elif name.startswith("cmpxchg"):
                    if accumulator & mask == old:
                        new = REPLACEMENT & mask
                    else:
                        result = old
                else:
                    result = old
                    if signed and old & (1 << (size * 8 - 1)):
                        result = (old - (1 << (size * 8))) & ((1 << signed) - 1)
                data[position:position + size] = new.to_bytes(size, "little")
                expected += struct.pack("<Q", result)
                names.append(f"{name} displacement={displacement} offset={position:#x}")
                if name.startswith("xadd"):
                    source, sign = accumulator & mask, 1 << (size * 8 - 1)
                    flags = int(old + source > mask)
                    flags |= int((new & 255).bit_count() % 2 == 0) << 2
                    flags |= (old ^ source ^ new) & 0x10
                    flags |= int(new == 0) << 6
                    flags |= int(bool(new & sign)) << 7
                    flags |= int(bool(~(old ^ source) & (old ^ new) & sign)) << 11
                    code += b"\x49\x89\x96" + struct.pack("<i", len(expected))
                    expected += struct.pack("<Q", flags)
                    names.append(f"{name} flags displacement={displacement} offset={position:#x}")
    for address, size in ((output_base, len(expected)), (data_base, len(data))):
        code += bytes.fromhex("b8 01 00 00 00 bf 01 00 00 00")
        code += b"\x48\xbe" + struct.pack("<Q", address)
        code += b"\xba" + struct.pack("<I", size) + bytes.fromhex("0f 05")
    code += bytes.fromhex("b8 3c 00 00 00 31 ff 0f 05")
    addresses = {}
    for name, function in functions.items():
        addresses[name] = code_base + len(code)
        code += function
    for offset, function in calls:
        struct.pack_into("<i", code, offset, addresses[function] - code_base - offset - 4)
    code.extend(bytes((-len(code)) % 4096))
    assert len(code) < data_base - code_base
    code[:64] = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9),
                            2, 62, 1, code_base + 0x200, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", code, 64, 1, 5, 0, code_base, code_base,
                     len(code), len(code), 4096)
    struct.pack_into("<IIQQQQQQ", code, 120, 1, 6, len(code), data_base, data_base,
                     len(data), output_base - data_base + len(expected), 4096)
    initial = bytes((i * 97 + 0x5B) & 255 for i in range(len(data)))
    path.write_bytes(code + initial)
    path.chmod(0o700)
    return bytes(expected + data), names


def main():
    binary = Path(sys.argv[1] if len(sys.argv) > 1 else "build/box64").resolve()
    with tempfile.TemporaryDirectory(prefix="box64-memory-paths-") as directory:
        guest = Path(directory) / "memory-paths"
        expected, names = make_guest(guest, sys.argv[2] if len(sys.argv) > 2 else "scalar")
        env = {key: value for key, value in os.environ.items() if not key.startswith("BOX64_")}
        env.update(BOX64_NORCFILES="1", BOX64_NOBANNER="1", BOX64_LOG="0", BOX64_SHOWSEGV="0",
                   BOX64_DYNACACHE="0", BOX64_DYNAREC_BIGBLOCK="0")
        failures = 0
        for level in (0, 1, 2, 3):
            for disable in ("", "uscat", "lrcpc", "lrcpc2"):
                env.update(BOX64_DYNAREC_STRONGMEM=str(level), BOX64_DYNAREC_NOHOSTEXT=disable)
                result = subprocess.run([str(binary), str(guest)], env=env,
                                        capture_output=True, timeout=30)
                label = f"STRONGMEM={level} NOHOSTEXT={disable or 'none'}"
                if result.returncode == 0 and result.stdout == expected:
                    print(f"PASS: {label}: {len(names)} operations and final memory", flush=True)
                    continue
                failures += 1
                print(f"FAIL: {label}: exit={result.returncode}, bytes={len(result.stdout)}/{len(expected)}")
                if len(result.stdout) == len(expected):
                    bad = next(i for i, pair in enumerate(zip(result.stdout, expected)) if pair[0] != pair[1])
                    print(names[bad // 8] if bad < len(names) * 8 else f"final memory byte {bad - len(names) * 8:#x}")
                    offset = bad // 8 * 8
                    print("got", result.stdout[offset:offset + 8].hex(), "expected", expected[offset:offset + 8].hex())
                print(result.stderr[-1500:].decode(errors="replace"))
        return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
