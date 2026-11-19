# SPDX-License-Identifier: MIT
"""Contend on x86 atomic counters or an XCHG spinlock through Box64 pthreads."""
import os
from pathlib import Path
import resource
import struct
import subprocess
import sys
import tempfile


def make_guest(path, displacement, width=64, iterations=100000, operation="xadd"):
    base, data = 0x400000, 0x402000
    image = bytearray(0x2000)
    image[:64] = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9),
                            2, 62, 1, base + 0x200, 64, 0, 0, 64, 56, 3, 0, 0, 0)
    for i, (kind, flags, offset, address, size) in enumerate([
        (1, 5, 0, base, 4096), (1, 6, 4096, data, 4096),
        (2, 6, 0x1100, data + 0x100, 160),
    ]):
        struct.pack_into("<IIQQQQQQ", image, 64 + 56 * i, kind, flags, offset,
                         address, address, size, size, 4096 if kind == 1 else 8)
    symbols = ["pthread_create", "pthread_join"]
    strings = bytearray(b"\0libc.so.6\0")
    for i, name in enumerate(symbols, 1):
        struct.pack_into("<IBBHQQ", image, 0x1400 + i * 24, len(strings), 0x12, 0, 0, 0, 0)
        strings.extend(name.encode() + b"\0")
        struct.pack_into("<QQq", image, 0x1500 + (i - 1) * 24,
                         data + (i - 1) * 8, (i << 32) | 6, 0)
    image[0x1300:0x1300 + len(strings)] = strings
    struct.pack_into("<6I", image, 0x1480, 1, 3, 1, 0, 2, 0)
    for i, entry in enumerate([(1, 1), (5, data + 0x300), (10, len(strings)),
                               (6, data + 0x400), (11, 24), (4, data + 0x480),
                               (7, data + 0x500), (8, 48), (9, 24), (0, 0)]):
        struct.pack_into("<QQ", image, 0x1100 + i * 16, *entry)
    code, worker_relocations = bytearray(), []

    def emit(value):
        code.extend(bytes.fromhex(value))

    def imm(opcode, value):
        emit(opcode)
        code.extend(struct.pack("<I", value))

    def call(address):
        emit("ff 15")
        code.extend(struct.pack("<i", address - (base + 0x200 + len(code) + 4)))

    for thread in range(2):
        imm("bf", data + 0x800 + thread * 8)  # pthread_t *
        emit("31 f6 ba")  # attr=NULL; function address
        worker_relocations.append(len(code))
        code.extend(bytes(4))
        if operation == "xor":
            imm("b9", data + 0xA00 + thread * 8)  # each worker's count of observed old-one bits
        else:
            emit("31 c9")  # arg=NULL
        call(data)
        emit("85 c0 74 09 89 c7 b8 3c 00 00 00 0f 05")  # fail on create error
    imm("bf", data + 0x900)
    emit("c7 07 01 00 00 00")  # release both workers
    for thread in range(2):
        imm("bf", data + 0x800 + thread * 8)
        emit("48 8b 3f 31 f6")  # pthread_join(tid, NULL)
        call(data + 8)
        emit("85 c0 74 09 89 c7 b8 3c 00 00 00 0f 05")
    if operation == "xor":
        imm("bf", data + 0xC00 + displacement)
        emit("48 8b 07 48 85 c0 74 0c bf 03 00 00 00 b8 3c 00 00 00 0f 05")
        imm("bf", data + 0xA00)
        emit("48 8b 07 48 03 47 08")
        imm("bf", data + 0xD00)
        emit("48 89 07")
    imm("be", data + (0xD00 if operation in ("xchg_lock", "lock_xchg_lock", "xor") else 0xC00 + displacement))
    emit("ba 08 00 00 00 bf 01 00 00 00 b8 01 00 00 00 0f 05")
    emit("31 ff b8 3c 00 00 00 0f 05")

    worker_address = base + 0x200 + len(code)
    if operation == "xor":
        emit("49 89 f8 45 31 c9")  # r8=thread output pointer, r9=old-one count
    imm("bf", data + 0x900)
    emit("83 3f 00 74 fb")  # wait until parent releases us
    imm("bf", data + 0xC00 + displacement)
    imm("b9", iterations)
    loop = len(code)
    if operation == "xadd":
        emit("b8 01 00 00 00")
        emit({16: "f0 66 0f c1 07", 32: "f0 0f c1 07", 64: "f0 48 0f c1 07"}[width])
    elif operation == "cmpxchg":
        emit({16: "0f b7 07", 32: "8b 07", 64: "48 8b 07"}[width])
        retry = len(code)
        emit("48 8d 50 01" if width == 64 else "8d 50 01")  # replacement = observed + 1
        emit({16: "f0 66 0f b1 17", 32: "f0 0f b1 17", 64: "f0 48 0f b1 17"}[width])
        emit("0f 85")
        code.extend(struct.pack("<i", retry - len(code) - 4))
    elif operation in ("add", "sub", "xor"):
        if operation == "sub":
            emit("48 c7 c0 ff ff ff ff" if width == 64 else "b8 ff ff ff ff")
        else:
            emit("b8 01 00 00 00")
        emit("f0")
        if width == 16:
            emit("66")
        elif width == 64:
            emit("48")
        emit({"add": "01 07", "sub": "29 07", "xor": "31 07"}[operation])
        if operation == "xor":
            emit("0f 94 c2 0f b6 d2 49 01 d1")  # ZF means old value was one
    elif operation in ("xchg_lock", "lock_xchg_lock"):
        imm("be", data + 0xD00)  # a separate counter protected by the guest spinlock
        retry = len(code)
        emit("b8 01 00 00 00")
        if operation == "lock_xchg_lock":
            emit("f0")
        emit({16: "66 87 07", 32: "87 07", 64: "48 87 07"}[width])
        emit("85 c0 0f 85")
        code.extend(struct.pack("<i", retry - len(code) - 4))
        emit("48 ff 06")  # non-atomic increment, valid only with exclusive ownership
        emit("31 c0")
        if operation == "lock_xchg_lock":
            emit("f0")
        emit({16: "66 87 07", 32: "87 07", 64: "48 87 07"}[width])  # atomic unlock, even across a cache line
    else:
        raise ValueError(operation)
    emit("ff c9 0f 85")
    code.extend(struct.pack("<i", loop - len(code) - 4))
    if operation == "xor":
        emit("4d 89 08")  # save sum after the final toggle
    emit("31 c0 c3")
    for offset in worker_relocations:
        struct.pack_into("<I", code, offset, worker_address)
    assert 0x200 + len(code) < 4096
    image[0x200:0x200 + len(code)] = code
    path.write_bytes(image)
    path.chmod(0o700)
    if operation == "xor":
        return iterations
    return iterations * 2 if operation in ("xchg_lock", "lock_xchg_lock") else (iterations * 2) & ((1 << width) - 1)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    binary = Path(sys.argv[1] if len(sys.argv) > 1 else "build/box64").resolve()
    operation = sys.argv[2] if len(sys.argv) > 2 else "xadd"
    env = {key: value for key, value in os.environ.items() if not key.startswith("BOX64_")}
    env.update(BOX64_NORCFILES="1", BOX64_NOBANNER="1", BOX64_LOG="0",
               BOX64_DYNACACHE="0", BOX64_DYNAREC_BIGBLOCK="0")
    failures = 0
    with tempfile.TemporaryDirectory(prefix="box64-atomic-contention-") as directory:
        guest = Path(directory) / "counter"
        for width in (32, 64):
            # Every alignment wholly contained in a 16-byte atomic block.
            for displacement in range(17 - width // 8):
                expected = make_guest(guest, displacement, width, operation=operation)
                for level in (1, 2, 3):
                    for disabled in ("uscat", "", "uscat,atomics", "atomics"):
                        env.update(BOX64_DYNAREC_NOHOSTEXT=disabled, BOX64_DYNAREC_STRONGMEM=str(level))
                        result = subprocess.run([str(binary), str(guest)], env=env,
                                                capture_output=True, timeout=20)
                        actual = int.from_bytes(result.stdout, "little") if len(result.stdout) == 8 else None
                        passed = result.returncode == 0 and actual == expected
                        failures += not passed
                        print(f"{'PASS' if passed else 'FAIL'}: width={width}, offset={displacement}, "
                              f"STRONGMEM={level}, NOHOSTEXT={disabled or 'none'}: "
                              f"counter={actual}/{expected}, exit={result.returncode}", flush=True)
                        if result.returncode:
                            print(result.stderr[-1000:].decode(errors="replace"))
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
