# SPDX-License-Identifier: MIT
"""A failed host advisory syscall during JIT must not change guest errno."""
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


def make_guest(path):
    image = bytearray(0x3000)
    image[:64] = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9),
                             2, 62, 1, 0x400200, 64, 0, 0, 64, 56, 4, 0, 0, 0)
    headers = [(1, 5, 0, 0x400000, 4096), (1, 6, 0x1000, 0x402000, 4096),
               (1, 7, 0x2000, 0x410000, 4096), (2, 6, 0x1100, 0x402100, 160)]
    for i, (kind, flags, offset, address, size) in enumerate(headers):
        struct.pack_into("<IIQQQQQQ", image, 64 + 56 * i,
                         kind, flags, offset, address, address, size, size, 4096 if kind == 1 else 8)
    strings = b"\0libc.so.6\0__errno_location\0"
    image[0x1300:0x1300 + len(strings)] = strings
    struct.pack_into("<IBBHQQ", image, 0x1418, 11, 0x12, 0, 0, 0, 0)
    struct.pack_into("<IIIII", image, 0x1480, 1, 2, 1, 0, 0)
    struct.pack_into("<QQq", image, 0x1500, 0x402000, (1 << 32) | 6, 0)
    dynamic = [(1, 1), (5, 0x402300), (10, len(strings)), (6, 0x402400),
               (11, 24), (4, 0x402480), (7, 0x402500), (8, 24), (9, 24), (0, 0)]
    for i, entry in enumerate(dynamic):
        struct.pack_into("<QQ", image, 0x1100 + 16 * i, *entry)
    code = bytearray(b"\xff\x15" + struct.pack("<i", 0x402000 - 0x400206))
    code += bytes.fromhex("48 89 c3 c7 03 0b 00 00 00")  # errno pointer; errno = EAGAIN
    code += b"\xe8" + struct.pack("<i", 0x410000 - (0x400200 + len(code) + 5))
    code += bytes.fromhex("8b 3b b8 3c 00 00 00 0f 05")  # exit(*errno)
    image[0x200:0x200 + len(code)] = code
    image[0x2000] = 0xc3  # RET, compiled only after errno was set
    path.write_bytes(image)
    path.chmod(0o700)


INJECTOR = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
int mprotect(void* address, size_t size, int prot)
{
    int result = syscall(SYS_mprotect, address, size, prot);
    uintptr_t start = (uintptr_t)address;
    if (!result && start <= 0x410000 && start + size > 0x410000 &&
        !(prot & PROT_WRITE) && errno == EAGAIN) {
        // Like a rejected MADV_HUGEPAGE hint; deliberately invalid alignment.
        syscall(SYS_madvise, (void*)1, 4096, MADV_HUGEPAGE);
        int error = errno;
        syscall(SYS_write, 2, "injected_madvise\n", 17);
        errno = error;
    }
    return result;
}
'''


def main():
    binary = Path(sys.argv[1] if len(sys.argv) > 1 else "build/box64").resolve()
    with tempfile.TemporaryDirectory(prefix="box64-errno-") as directory:
        directory = Path(directory)
        guest = directory / "guest-errno"
        make_guest(guest)
        source, library = directory / "inject.c", directory / "inject.so"
        source.write_text(INJECTOR)
        subprocess.run([os.environ.get("CC", "cc"), "-shared", "-fPIC", "-O2",
                        str(source), "-o", str(library)], check=True)
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("BOX64_") and key != "LD_PRELOAD"}
        env.update(BOX64_NORCFILES="1", BOX64_LOG="0", BOX64_DYNAREC_BIGBLOCK="0")
        for inject in (False, True):
            if inject:
                env["LD_PRELOAD"] = str(library)
            result = subprocess.run([str(binary), str(guest)], env=env,
                                    text=True, capture_output=True, timeout=20)
            if inject and "injected_madvise" not in result.stderr:
                raise AssertionError("fault injection did not run: " + result.stdout + result.stderr)
            if result.returncode != 11:
                raise AssertionError(f"guest errno = {result.returncode}, expected EAGAIN (11); "
                                     f"injection={inject}\n{result.stdout}{result.stderr}")
        print("PASS: guest errno survives JIT compilation with a failed host syscall")


if __name__ == "__main__":
    main()
