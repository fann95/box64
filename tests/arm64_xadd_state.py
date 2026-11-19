# SPDX-License-Identifier: MIT
"""Exercise the XADD slow path with live GPR, AVX and x87 state."""
import os
from pathlib import Path
import resource
import struct
import subprocess
import sys
import tempfile
from arm64_atomic_edges import arithmetic_flags


def text_section(obj):
    shoff = struct.unpack_from("<Q", obj, 40)[0]
    shsize, shcount, strindex = struct.unpack_from("<HHH", obj, 58)
    headers = [struct.unpack_from("<IIQQQQIIQQ", obj, shoff + i * shsize) for i in range(shcount)]
    strings = obj[headers[strindex][4]:headers[strindex][4] + headers[strindex][5]]
    result = None
    for header in headers:
        name = strings[header[0]:].split(b"\0", 1)[0]
        assert name != b".rela.text" or not header[5], "unexpected assembly relocation"
        if name == b".text":
            result = obj[header[4]:header[4] + header[5]]
    assert result
    return result


def make_guest(directory, source, width, operation="xadd", position=0x801,
               compare_matches=False, carry_mode="push1"):
    data_base, output_base = 0x500000, 0x510000
    address = data_base + position
    registers = ["rax", "rcx", "rdx", "rbx", "rbp", "rsi", "rdi"] + [f"r{i}" for i in range(8, 16)]
    values = {name: 0x1020304050607080 + i for i, name in enumerate(registers)}
    values["rdi"] = address
    initial = 0xFEDCBA987FFFFFFF
    mask, sign = (1 << width) - 1, 1 << (width - 1)
    if operation == "cmpxchg" and compare_matches:
        initial = (initial & ~mask) | (values["rax"] & mask)
    old, operand = initial & mask, values[source] & mask
    carry = int(carry_mode[-1])
    flag_mask = 0x8C5 if operation in ("and", "or", "xor") else 0x8D5
    if carry_mode.startswith("cmp"):
        flags_input = 0 if carry else 2
        initial_flags = arithmetic_flags(flags_input, 1, (flags_input - 1) & ((1 << 64) - 1), 64, subtract=True)
    elif carry_mode.startswith("add"):
        flags_input = (1 << 64) - 1 if carry else 0
        initial_flags = arithmetic_flags(flags_input, 1, (flags_input + 1) & ((1 << 64) - 1), 64)
    else:
        flags_input, initial_flags = 0, (0x8D5 & ~1) | carry
    after = values.copy()
    if operation in ("add", "xadd", "adc"):
        carry_in = carry if operation == "adc" else 0
        new = (old + operand + carry_in) & mask
        flags = arithmetic_flags(old, operand, new, width, carry_in)
    elif operation == "sub":
        new = (old - operand) & mask
        flags = arithmetic_flags(old, operand, new, width, subtract=True)
    elif operation in ("and", "or", "xor"):
        new = {"and": old & operand, "or": old | operand, "xor": old ^ operand}[operation]
        flags = arithmetic_flags(0, 0, new, width) & 0xC4
    elif operation in ("xchg", "lock_xchg"):
        new, flags = operand, initial_flags
    elif operation == "cmpxchg":
        compare = values["rax"] & mask
        flags = arithmetic_flags(compare, old, (compare - old) & mask, width, subtract=True)
        new = operand if compare == old else old
        if compare != old:
            after["rax"] = (values["rax"] & ~mask) | old if width == 16 else old
    else:
        raise ValueError(operation)
    if operation in ("xadd", "xchg", "lock_xchg"):
        after[source] = (values[source] & ~mask) | old if width == 16 else old
    expected = bytearray(0x420)
    data = bytearray(4096)
    data[:512] = bytes((i * 97 + 3) & 255 for i in range(512))
    struct.pack_into("<dH", data, 0x400, 1.25, 0x37F)
    struct.pack_into("<Q", data, 0x420, flags_input)
    struct.pack_into("<Q", data, address - data_base, initial)
    lines = [".intel_syntax noprefix", ".text", f"mov rsi, {data_base}"]
    for i in range(16):
        lines.append(f"vmovdqu ymm{i}, [rsi+{32 * i}]")
    lines += ["fldcw word ptr [rsi+0x408]", "fld qword ptr [rsi+0x400]"]
    for name, value in values.items():
        lines.append(f"mov {name}, {value}")
    lines.append(f"mov qword ptr [{data_base + 0x900}], rsp")
    if carry_mode.startswith("push"):
        lines += [f"push {0x202 | initial_flags}", "popfq"]
    else:
        lines.append(f"{carry_mode[:3]} qword ptr [{data_base + 0x420}], 1")
    operands = {16: {"rax": "ax", "rdi": "di", "r8": "r8w", "r15": "r15w"},
                32: {"rax": "eax", "rdi": "edi", "r8": "r8d", "r15": "r15d"}}
    register = source if width == 64 else operands[width][source]
    lock = "" if operation == "xchg" else "lock "
    size = {16: "word", 32: "dword", 64: "qword"}[width]
    mnemonic = "xchg" if operation == "lock_xchg" else operation
    lines.append(f"{lock}{mnemonic} {size} ptr [rdi], {register}")
    for i, name in enumerate(registers):
        lines.append(f"mov qword ptr [{output_base + i * 8}], {name}")
        struct.pack_into("<Q", expected, i * 8, after[name])
    lines += ["pushfq", "pop rax", f"and eax, {flag_mask}", f"mov qword ptr [{output_base + 0x408}], rax"]
    for i in range(16):
        lines.append(f"vmovdqu [{output_base + 0x100 + 32 * i}], ymm{i}")
    expected[0x100:0x300] = data[:512]
    lines += [f"fstp qword ptr [{output_base + 0x400}]",
              f"fnstcw word ptr [{output_base + 0x418}]",
              f"mov rax, qword ptr [{address}]", f"mov qword ptr [{output_base + 0x410}], rax",
              f"cmp rsp, qword ptr [{data_base + 0x900}]", "jne .Lfail",
              f"mov esi, {output_base}", f"mov edx, {len(expected)}", "mov edi, 1", "mov eax, 1", "syscall",
              "xor edi, edi", "mov eax, 60", "syscall", ".Lfail:", "mov edi, 2", "mov eax, 60", "syscall"]
    struct.pack_into("<dQQH", expected, 0x400, 1.25, flags & flag_mask, (initial & ~mask) | new, 0x37F)
    assembly, obj = directory / "state.s", directory / "state.o"
    assembly.write_text("\n".join(lines) + "\n")
    subprocess.run(["clang", "--target=x86_64-linux-gnu", "-c", str(assembly), "-o", str(obj)], check=True)
    code = text_section(obj.read_bytes())
    assert 512 + len(code) <= 4096
    image = bytearray(4096)
    image[:64] = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9),
                            2, 62, 1, 0x400200, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", image, 64, 1, 5, 0, 0x400000, 0x400000, 4096, 4096, 4096)
    struct.pack_into("<IIQQQQQQ", image, 120, 1, 6, 4096, data_base, data_base,
                     len(data), output_base - data_base + len(expected), 4096)
    image[512:512 + len(code)] = code
    guest = directory / "state"
    guest.write_bytes(image + data)
    guest.chmod(0o700)
    return guest, expected


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    binary = Path(sys.argv[1] if len(sys.argv) > 1 else "build/box64").resolve()
    env = {key: value for key, value in os.environ.items() if not key.startswith("BOX64_")}
    env.update(BOX64_NORCFILES="1", BOX64_NOBANNER="1", BOX64_LOG="0",
               BOX64_DYNACACHE="0", BOX64_DYNAREC_STRONGMEM="3")
    with tempfile.TemporaryDirectory(prefix="box64-xadd-state-") as directory:
        for width in (32, 64):
            for source in ("rax", "rdi", "r8", "r15"):
                guest, expected = make_guest(Path(directory), source, width)
                for disabled in ("uscat", "atomics"):
                    env["BOX64_DYNAREC_NOHOSTEXT"] = disabled
                    result = subprocess.run([str(binary), str(guest)], env=env,
                                            capture_output=True, timeout=20)
                    assert result.returncode == 0, result.stderr.decode(errors="replace")
                    if result.stdout != expected:
                        for i, (got, want) in enumerate(zip(result.stdout, expected)):
                            if got != want:
                                raise AssertionError(f"width={width}, source={source}, {disabled}: "
                                                     f"offset={i:#x}: got {got:#x}, expected {want:#x}")
                        raise AssertionError(f"output size {len(result.stdout)}/{len(expected)}")
                    print(f"PASS: width={width}, source={source}, NOHOSTEXT={disabled}: GPR, AVX, x87 and flags")


if __name__ == "__main__":
    main()
