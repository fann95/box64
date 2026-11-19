# SPDX-License-Identifier: MIT
"""Exercise GSSAPI OID wrappers with real 64-bit guest pointers and local data."""
import argparse
import os
from pathlib import Path
import resource
import subprocess
import tempfile

from thread_cleanup_dso import elf


SOURCE = r"""
entry:
    and rsp, -16
    sub rsp, 128
    mov r12, rsp
    mov rax, rsp
    shr rax, 32
    test rax, rax
    jz fail_address
    mov rdi, rsp
    xor eax, eax
    mov ecx, 16
    rep stosq
    # Check a newly exposed function before exercising the old pointer wrappers.
    xor edi, edi
    lea rsi, [rip+oid_to_str_name]
    call [rip+slot_dlsym]
    test rax, rax
    jz fail_symbol
    mov r13, rax
    mov rdi, r12
    lea rsi, [r12+8]
    call [rip+slot_gss_create_empty_oid_set]
    test eax, eax
    jnz fail_create
    mov dword ptr [r12+32], 9
    lea rax, [rip+oid_bytes]
    mov [r12+40], rax
    mov rdi, r12
    lea rsi, [r12+32]
    lea rdx, [r12+8]
    call [rip+slot_gss_add_oid_set_member]
    test eax, eax
    jnz fail_add
    mov rax, [r12+8]
    test rax, rax
    jz fail_count
    cmp qword ptr [rax], 1
    jne fail_count
    mov rdi, r12
    lea rsi, [r12+32]
    mov rdx, [r12+8]
    lea rcx, [r12+56]
    call [rip+slot_gss_test_oid_set_member]
    test eax, eax
    jnz fail_member
    cmp dword ptr [r12+56], 1
    jne fail_member
    mov rdi, r12
    lea rsi, [r12+32]
    lea rdx, [r12+64]
    call r13
    test eax, eax
    jnz fail_string
    cmp qword ptr [r12+64], 0
    je fail_string
    cmp qword ptr [r12+72], 0
    je fail_string
    mov rdi, r12
    lea rsi, [r12+64]
    call [rip+slot_gss_release_buffer]
    test eax, eax
    jnz fail_release
    mov rdi, r12
    lea rsi, [r12+8]
    call [rip+slot_gss_release_oid_set]
    test eax, eax
    jnz fail_release
    cmp qword ptr [r12+8], 0
    jne fail_release
    xor edi, edi
    jmp finish
fail_address: mov edi, 1; jmp finish
fail_symbol: mov edi, 2; jmp finish
fail_create: mov edi, 3; jmp finish
fail_add: mov edi, 4; jmp finish
fail_count: mov edi, 5; jmp finish
fail_member: mov edi, 6; jmp finish
fail_string: mov edi, 7; jmp finish
fail_release: mov edi, 8
finish:
    mov eax, 231
    syscall
oid_bytes: .byte 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02
.org 0x1000
slot_dlsym: .quad 0
slot_gss_create_empty_oid_set: .quad 0
slot_gss_add_oid_set_member: .quad 0
slot_gss_test_oid_set_member: .quad 0
slot_gss_release_buffer: .quad 0
slot_gss_release_oid_set: .quad 0
oid_to_str_name: .asciz "gss_oid_to_str"
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("box64", type=Path)
    parser.add_argument("--interpreter", action="store_true")
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    environment = {key: value for key, value in os.environ.items() if not key.startswith("BOX64_")}
    environment.update(BOX64_NORCFILES="1", BOX64_LOG="0", BOX64_NOBANNER="1", BOX64_SHOWSEGV="0",
                       BOX64_DYNAREC="0" if args.interpreter else "1", BOX64_DYNACACHE="0")
    with tempfile.TemporaryDirectory(prefix="box64-gssapi-oid-") as directory:
        guest = elf(Path(directory), "gssapi-oid", SOURCE,
                    ["dlsym", "gss_create_empty_oid_set", "gss_add_oid_set_member",
                     "gss_test_oid_set_member", "gss_release_buffer", "gss_release_oid_set"],
                    dependencies=["libgssapi_krb5.so.2"])
        result = subprocess.run([str(args.box64.resolve()), str(guest)], env=environment,
                                capture_output=True, text=True, timeout=15)
    if result.returncode:
        names = {1: "guest pointer was not above 4 GiB", 2: "gss_oid_to_str is unavailable",
                 3: "create set", 4: "add OID", 5: "set count", 6: "test membership",
                 7: "OID to string", 8: "release allocations"}
        print(f"FAIL: {names.get(result.returncode, 'process failure')}; exit={result.returncode}")
        print((result.stdout + result.stderr)[-2000:])
        return 1
    print("PASS: GSSAPI create/add/test/string/release with pointers above 4 GiB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
