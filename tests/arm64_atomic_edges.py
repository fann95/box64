# SPDX-License-Identifier: MIT
"""Check locked x86 operations at every alignment, then contend on guest locks.

Usage: python3 -B tests/arm64_atomic_edges.py [build/box64] [--quick]
Use --mode semantics or --mode contention to run one part independently.
"""
import argparse
from collections import Counter
import os
from pathlib import Path
import resource
import struct
import subprocess
import tempfile

from arm64_unaligned_atomics import make_guest as make_counter


ARITHMETIC_FLAGS = 0x8D5
OPCODES = {"add": "01 0f", "adc": "11 0f", "and": "21 0f", "or": "09 0f",
           "sub": "29 0f", "xor": "31 0f",
           "xadd": "0f c1 0f", "cmpxchg": "0f b1 0f", "xchg": "87 0f", "lock_xchg": "87 0f"}


def arithmetic_flags(left, right, result, width, carry=0, subtract=False):
    mask, sign = (1 << width) - 1, 1 << (width - 1)
    flags = int(left < right) if subtract else int(left + right + carry > mask)
    flags |= int((result & 255).bit_count() % 2 == 0) << 2
    flags |= (left ^ right ^ result) & 0x10
    flags |= int(result == 0) << 6 | int(bool(result & sign)) << 7
    overflow = (left ^ right) & (left ^ result) if subtract else ~(left ^ right) & (left ^ result)
    return flags | int(bool(overflow & sign)) << 11


def make_semantics(path, operation, width, position):
    base, data_base, output_base = 0x400000, 0x500000, 0x510000
    mask, sign, size = (1 << width) - 1, 1 << (width - 1), width // 8
    code, expected = bytearray(512), bytearray()
    cases = ((0, 0, 0), (mask, 1, 0), (mask, 0, 1), (sign - 1, 0, 1),
             (sign, mask, 1), (15, 1, 1), (0x55AA55AA55AA55AA & mask, 0xAA55AA55AA55AA55 & mask, 0))

    def emit(hex_bytes):
        code.extend(bytes.fromhex(hex_bytes))

    def imm64(opcode, value):
        emit(opcode)
        code.extend(struct.pack("<Q", value))

    def write(address, count):
        emit("b8 01 00 00 00 bf 01 00 00 00")
        imm64("48 be", address)
        emit("ba")
        code.extend(struct.pack("<I", count))
        emit("0f 05")

    for index, (old, operand, carry) in enumerate(cases):
        neighborhood = bytearray((i * 37 + 0x53) & 255 for i in range(48))
        neighborhood[16:16 + size] = old.to_bytes(size, "little")
        imm64("48 bf", data_base + position - 16)
        for offset in range(0, 48, 8):
            imm64("48 ba", int.from_bytes(neighborhood[offset:offset + 8], "little"))
            emit("48 89 57")
            code.append(offset)
        accumulator = 0x123456789ABCDEF0
        source = operand if width == 64 else 0xFEDCBA9800000000 | operand
        if operation == "cmpxchg":
            accumulator = old if index % 2 else old ^ 1
            if width != 64:
                accumulator |= 0x1234567800000000
        imm64("48 b8", accumulator)
        imm64("48 b9", source)
        imm64("48 bf", data_base + position)
        initial_flags = (ARITHMETIC_FLAGS & ~1) | carry
        emit("68")
        code.extend(struct.pack("<I", 0x202 | initial_flags))
        emit("9d")
        if operation != "xchg":
            emit("f0")
        if width == 16:
            emit("66")
        elif width == 64:
            emit("48")
        emit(OPCODES[operation])
        emit("48 a3")
        code.extend(struct.pack("<Q", output_base))
        emit("48 89 0c 25")
        code.extend(struct.pack("<I", output_base + 8))
        flag_mask = ARITHMETIC_FLAGS & ~0x10 if operation in ("and", "or", "xor") else ARITHMETIC_FLAGS
        emit("9c 5a 81 e2")
        code.extend(struct.pack("<I", flag_mask))
        emit("48 89 14 25")
        code.extend(struct.pack("<I", output_base + 16))
        new, out_rax, out_rcx = old, accumulator, source
        if operation in ("add", "adc", "xadd"):
            carry_in = carry if operation == "adc" else 0
            new = (old + operand + carry_in) & mask
            flags = arithmetic_flags(old, operand, new, width, carry_in)
        elif operation == "sub":
            new = (old - operand) & mask
            flags = arithmetic_flags(old, operand, new, width, subtract=True)
        elif operation in ("and", "or", "xor"):
            new = {"and": old & operand, "or": old | operand, "xor": old ^ operand}[operation]
            flags = arithmetic_flags(0, 0, new, width) & 0xC4
        elif operation == "cmpxchg":
            compare = accumulator & mask
            flags = arithmetic_flags(compare, old, (compare - old) & mask, width, subtract=True)
            if compare == old:
                new = operand
            else:
                out_rax = (accumulator & ~mask) | old if width == 16 else old
        else:
            new, flags = operand, initial_flags
        if operation in ("xadd", "xchg", "lock_xchg"):
            out_rcx = (source & ~mask) | old if width == 16 else old
        neighborhood[16:16 + size] = new.to_bytes(size, "little")
        expected.extend(struct.pack("<QQQ", out_rax, out_rcx, flags & flag_mask))
        expected.extend(neighborhood)
        write(output_base, 24)
        write(data_base + position - 16, len(neighborhood))
    emit("31 ff b8 3c 00 00 00 0f 05")
    code.extend(bytes((-len(code)) % 4096))
    code[:64] = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9),
                            2, 62, 1, base + 512, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", code, 64, 1, 5, 0, base, base, len(code), len(code), 4096)
    struct.pack_into("<IIQQQQQQ", code, 120, 1, 6, len(code), data_base, data_base,
                     0x3000, output_base - data_base + 4096, 4096)
    path.write_bytes(code + bytes(0x3000))
    path.chmod(0o700)
    return bytes(expected)


def run(binary, guest, env, timeout):
    try:
        result = subprocess.run([str(binary), str(guest)], env=env,
                                capture_output=True, timeout=timeout)
        return result.returncode, result.stdout
    except subprocess.TimeoutExpired:
        return "timeout", b""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", default="build/box64")
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--mode", choices=("semantics", "contention", "all"), default="all")
    parser.add_argument("--within16", action="store_true", help="skip fields crossing a 16-byte boundary; report their count")
    parser.add_argument("--operations", nargs="+", choices=tuple(OPCODES), default=tuple(OPCODES),
                        help="semantic operations to check (contention selection is unchanged)")
    contention_ops = ("xadd", "cmpxchg", "xchg_lock", "lock_xchg_lock", "add", "sub", "xor")
    parser.add_argument("--contention-operations", nargs="+", choices=contention_ops, default=contention_ops,
                        help="threaded operations to check")
    parser.add_argument("--iterations", type=int, help="increments per worker; default 100000, or 50000 with --quick")
    parser.add_argument("--timeout", type=float, default=5, help="seconds allowed for each guest process")
    args = parser.parse_args()
    if args.timeout <= 0 or (args.iterations is not None and args.iterations <= 0):
        parser.error("timeout and iterations must be positive")
    binary = Path(args.binary).resolve()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = {key: value for key, value in os.environ.items() if not key.startswith("BOX64_")}
    env.update(BOX64_NORCFILES="1", BOX64_NOBANNER="1", BOX64_LOG="0", BOX64_SHOWSEGV="0",
               BOX64_DYNACACHE="0", BOX64_DYNAREC_BIGBLOCK="0", BOX64_DYNAREC_STRONGMEM="3")
    disabled_features = ("uscat", "") if args.quick else ("uscat", "", "uscat,atomics", "atomics")
    totals, failures = Counter(), Counter()
    examples, skipped = [], 0

    def record(group, label, passed, detail):
        totals[group] += 1
        if not passed:
            failures[group] += 1
            if len(examples) < 18:
                examples.append(f"{label}: {detail}")

    with tempfile.TemporaryDirectory(prefix="box64-atomic-edges-") as directory:
        guest = Path(directory) / "atomic-guest"
        if args.mode != "contention":
            positions = (0x1000, 0x1001, 0x1007, 0x100F, 0x103F, 0x1FFF) if args.quick else tuple(0x1000 + i for i in range(16)) + (0x103F, 0x1FFF)
            for operation in args.operations:
                widths = (32, 64) if operation in ("sub", "xor", "lock_xchg") else (16, 32, 64)
                for width in widths:
                    for position in positions:
                        if args.within16 and position % 16 + width // 8 > 16:
                            skipped += len(disabled_features)
                            continue
                        expected = make_semantics(guest, operation, width, position)
                        for disabled in disabled_features:
                            env["BOX64_DYNAREC_NOHOSTEXT"] = disabled
                            status, actual = run(binary, guest, env, args.timeout)
                            group = f"semantics {operation}{width}"
                            detail = f"exit={status}, bytes={len(actual)}/{len(expected)}"
                            if status == 0 and len(actual) == len(expected) and actual != expected:
                                byte = next(i for i, pair in enumerate(zip(actual, expected)) if pair[0] != pair[1])
                                detail += f", case={byte // 72}, byte={byte % 72}, got={actual[byte]:02x}, expected={expected[byte]:02x}"
                            record(group, f"{group} offset={position:#x} NOHOSTEXT={disabled or 'none'}", status == 0 and actual == expected, detail)
        if args.mode != "semantics":
            iterations = args.iterations if args.iterations is not None else (50000 if args.quick else 100000)
            for operation in args.contention_operations:
                for width in ((32, 64) if operation in ("sub", "xor", "lock_xchg_lock") else (16, 32, 64)):
                    for position in (0, 1, 7, 15, 63):
                        if args.within16 and position % 16 + width // 8 > 16:
                            skipped += len(disabled_features)
                            continue
                        expected = make_counter(guest, position, width, iterations, operation)
                        for disabled in disabled_features:
                            env["BOX64_DYNAREC_NOHOSTEXT"] = disabled
                            status, output = run(binary, guest, env, args.timeout)
                            actual = int.from_bytes(output, "little") if len(output) == 8 else None
                            group = f"contention {operation}{width}"
                            record(group, f"{group} offset={position} NOHOSTEXT={disabled or 'none'}", status == 0 and actual == expected,
                                   f"exit={status}, counter={actual}/{expected}")
    for group in totals:
        print(f"{'FAIL' if failures[group] else 'PASS'}: {group}: {totals[group] - failures[group]}/{totals[group]}")
    for example in examples:
        print("  " + example)
    print(f"TOTAL: {sum(totals.values()) - sum(failures.values())}/{sum(totals.values())} passed")
    if args.within16:
        print(f"SKIPPED: {skipped} cross-16-byte cases (not validated by this run)")
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
