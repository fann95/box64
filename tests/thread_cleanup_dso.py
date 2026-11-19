# SPDX-License-Identifier: MIT
"""Exercise real x86-64 TLS destructors after dlclose through Box64.

Builds a tiny dynamic ELF and DSO with clang's assembler, without an x86 sysroot.
The worker registers two destructors; the main thread closes the DSO before the
worker exits. One destructor registers a third, checking LIFO and reentrancy.
No crash is needed for the negative control: premature DSO finalization is
detected before the worker is allowed to call its destructors.
"""
import argparse
import os
from pathlib import Path
import resource
import struct
import subprocess
import tempfile


def assemble(directory, name, assembly):
    source, obj = directory / (name + ".S"), directory / (name + ".o")
    source.write_text(".intel_syntax noprefix\n.text\n" + assembly)
    subprocess.run(["clang", "-target", "x86_64-linux-gnu", "-c", str(source), "-o", str(obj)], check=True)
    raw = obj.read_bytes()
    shoff = struct.unpack_from("<Q", raw, 40)[0]
    shsize, shnum, shstrings = struct.unpack_from("<HHH", raw, 58)
    sections = [struct.unpack_from("<IIQQQQIIQQ", raw, shoff + i * shsize) for i in range(shnum)]
    names = sections[shstrings]
    strings = raw[names[4]:names[4] + names[5]]
    text_index = next(i for i, section in enumerate(sections)
                      if strings[section[0]:].split(b"\0", 1)[0] == b".text")
    section = sections[text_index]
    code = raw[section[4]:section[4] + section[5]]
    symbols = {}
    for section in sections:
        if section[1] == 4 and section[7] == text_index and section[5]:
            raise RuntimeError("Fixture assembly unexpectedly contains relocations")
        if section[1] != 2:
            continue
        names = sections[section[6]]
        strings = raw[names[4]:names[4] + names[5]]
        for offset in range(section[4], section[4] + section[5], section[9]):
            name_offset, info, other, index, value, size = struct.unpack_from("<IBBHQQ", raw, offset)
            if index == text_index:
                symbols[strings[name_offset:].split(b"\0", 1)[0].decode()] = value
    return code, symbols


def elf(directory, name, assembly, imports, exports=(), shared=False, fini=None, dependencies=(), lazy=()):
    code, labels = assemble(directory, name, assembly)
    assert 0x1000 <= len(code) <= 0x2000
    base = 0 if shared else 0x400000
    image = bytearray(0x3000)
    image[0x1000:0x1000 + len(code)] = code
    strings = bytearray(b"\0")

    def string(value):
        offset = len(strings)
        strings.extend(value.encode() + b"\0")
        return offset

    needed = [string(value) for value in ("libc.so.6", "libpthread.so.0", "libdl.so.2", *dependencies)]
    all_symbols = list(imports) + list(lazy) + list(exports)
    for index, symbol in enumerate(all_symbols, 1):
        value = base + 0x1000 + labels[symbol] if symbol in exports else 0
        struct.pack_into("<IBBHQQ", image, 0x800 + index * 24,
                         string(symbol), 0x12, 0, 1 if value else 0, value, 0)
    image[0x600:0x600 + len(strings)] = strings
    assert len(strings) <= 0x200 and (len(all_symbols) + 1) * 24 <= 0x300
    # One SysV hash bucket is sufficient for this small fixture.
    count = len(all_symbols) + 1
    struct.pack_into("<III", image, 0xB00, 1, count, 1)
    for index in range(count):
        struct.pack_into("<I", image, 0xB0C + index * 4,
                         index + 1 if 0 < index < count - 1 else 0)
    for index, symbol in enumerate(imports, 1):
        struct.pack_into("<QQq", image, 0xD00 + (index - 1) * 24,
                         base + 0x1000 + labels["slot_" + symbol], (index << 32) | 6, 0)
    dynamic = [(1, value) for value in needed]
    dynamic += [(5, base + 0x600), (10, len(strings)), (6, base + 0x800), (11, 24),
                (4, base + 0xB00), (7, base + 0xD00), (8, len(imports) * 24), (9, 24)]
    if lazy:
        for index, symbol in enumerate(lazy):
            slot = base + 0x1000 + labels["slot_" + symbol]
            struct.pack_into("<QQq", image, 0xE00 + index * 24,
                             slot, ((len(imports) + index + 1) << 32) | 7, 0)
            struct.pack_into("<Q", image, slot - base, base + 0x1000 + labels["plt_" + symbol])
        dynamic += [(3, base + 0x1000 + labels["plt_got"]), (20, 7),
                    (23, base + 0xE00), (2, len(lazy) * 24)]
    if fini:
        dynamic.append((13, base + 0x1000 + labels[fini]))
    dynamic.append((0, 0))
    for index, entry in enumerate(dynamic):
        struct.pack_into("<QQ", image, 0x400 + index * 16, *entry)
    struct.pack_into("<16sHHIQQQIHHHHHH", image, 0,
                     b"\x7fELF\x02\x01\x01" + bytes(9), 3 if shared else 2, 62, 1,
                     0 if shared else base + 0x1000 + labels["entry"], 64, 0, 0, 64, 56, 3, 0, 0, 0)
    for index, (kind, flags, offset, size) in enumerate(
            [(1, 5, 0, 0x2000), (1, 6, 0x2000, 0x1000), (2, 4, 0x400, len(dynamic) * 16)]):
        struct.pack_into("<IIQQQQQQ", image, 64 + index * 56,
                         kind, flags, offset, base + offset, base + offset,
                         size, size, 4096 if kind == 1 else 8)
    if lazy:
        names = b"\0.plt\0.shstrtab\0.dynamic\0.dynstr\0.dynsym\0"
        image[0xF00:0xF00 + len(names)] = names
        image.extend(bytes(6 * 64))
        struct.pack_into("<Q", image, 40, 0x3000)
        struct.pack_into("<HHH", image, 58, 64, 6, 2)
        plt = 0x1000 + labels["plt_start"]
        struct.pack_into("<IIQQQQIIQQ", image, 0x3040,
                         1, 1, 6, base + plt, plt, labels["plt_end"] - labels["plt_start"], 0, 0, 16, 0)
        struct.pack_into("<IIQQQQIIQQ", image, 0x3080,
                         6, 3, 0, 0, 0xF00, len(names), 0, 0, 1, 0)
        struct.pack_into("<IIQQQQIIQQ", image, 0x30C0,
                         names.index(b".dynamic"), 6, 2, base + 0x400, 0x400, len(dynamic) * 16, 4, 0, 8, 16)
        struct.pack_into("<IIQQQQIIQQ", image, 0x3100,
                         names.index(b".dynstr"), 3, 2, base + 0x600, 0x600, len(strings), 0, 0, 1, 0)
        struct.pack_into("<IIQQQQIIQQ", image, 0x3140,
                         names.index(b".dynsym"), 11, 2, base + 0x800, 0x800, count * 24, 4, 1, 8, 24)
    path = directory / name
    path.write_bytes(image)
    path.chmod(0o700)
    return path


DSO = r"""
register_destructors:
    push rbx
    sub rsp, 16
    mov rbx, rdi
    mov [rip+object], rdi
    mov dword ptr [rsp], REGISTRATIONS
register_first:
    lea rdi, [rip+first]
    mov rsi, rbx
    lea rdx, [rip+dso_handle]
    call [rip+slot___cxa_thread_atexit_impl]
    test eax, eax
    jnz registration_failed
    sub dword ptr [rsp], 1
    jnz register_first
    lea rdi, [rip+second]
    mov rsi, rbx
    lea rdx, [rip+dso_handle]
    call [rip+slot___cxa_thread_atexit_impl]
registration_failed:
    add rsp, 16
    pop rbx
    ret
first:
    mov esi, 1
    jmp record
second:
    push rbx
    mov rbx, rdi
    mov esi, 2
    call record
    lea rdi, [rip+third]
    mov rsi, rbx
    lea rdx, [rip+dso_handle]
    call [rip+slot___cxa_thread_atexit_impl]
    test eax, eax
    jz nested_ok
    mov dword ptr [rbx+28], 1
nested_ok:
    pop rbx
    ret
third:
    mov esi, 3
    jmp record
fourth:
    mov esi, 4
    jmp record
record:
.if USE_DEPENDENCY
    jmp [rip+slot_record_event]
.else
    mov eax, [rdi+12]
    mov [rdi+rax*4+64], esi
    inc dword ptr [rdi+12]
    ret
.endif
finalize:
    push rbx
    mov rbx, [rip+object]
    test rbx, rbx
    jz no_object
    inc dword ptr [rbx+8]
.if LOCAL_PARENT
    mov rdi, rbx
    call [rip+slot_finalize_event]
.endif
.if FINI_REGISTER
    lea rdi, [rip+fourth]
    mov rsi, rbx
    lea rdx, [rip+dso_handle]
    call [rip+slot___cxa_thread_atexit_impl]
    test eax, eax
    jz fini_registered
    mov dword ptr [rbx+28], 1
fini_registered:
.endif
.if FINI_REOPEN
    lea rdi, [rip+self_library]
    mov esi, 2
    call [rip+slot_dlopen]
    mov [rbx+40], rax
.endif
no_object:
    pop rbx
    ret
probe:
    mov eax, 0x12345678
    ret
plt_start:
plt_record_event:
    push 0
    jmp plt_common
plt_finalize_event:
    push 1
plt_common:
    push [rip+plt_got+8]
    jmp [rip+plt_got+16]
plt_end:
.org 0x1000
slot___cxa_thread_atexit_impl: .quad 0
slot_record_event: .quad 0
slot_dlopen: .quad 0
slot_finalize_event: .quad 0
plt_got: .quad 0, 0, 0
dso_handle: .quad 0
object: .quad 0
self_library: .asciz "SELF_LIBRARY"
"""


DEPENDENCY = r"""
record_event:
    mov [rip+object], rdi
    mov eax, [rdi+12]
    mov [rdi+rax*4+64], esi
    inc dword ptr [rdi+12]
    ret
finalize_event:
    inc dword ptr [rdi+36]
    ret
finalize:
    mov rax, [rip+object]
    test rax, rax
    jz no_object
    inc dword ptr [rax+32]
no_object:
    ret
.org 0x1000
object: .quad 0
"""

PARENT = r"""
parent_register:
    mov [rip+object], rdi
    jmp [rip+slot_register_destructors]
finalize:
    mov rax, [rip+object]
    test rax, rax
    jz no_object
    inc dword ptr [rax+48]
no_object:
    ret
.org 0x1000
slot_register_destructors: .quad 0
object: .quad 0
"""


def main_source(library, args):
    return r"""
entry:
    and rsp, -16
    mov r12d, ROUNDS
again:
    lea rdi, [rip+state]
    xor eax, eax
    mov ecx, 384
    rep stosq
    lea rdi, [rip+library]
    mov esi, 2
    call [rip+slot_dlopen]
    test rax, rax
    jz fail_open
    mov [rip+handle], rax
    mov rdi, rax
    lea rsi, [rip+symbol]
    call [rip+slot_dlsym]
    test rax, rax
    jz fail_symbol
    mov [rip+registrar], rax
    lea rdi, [rip+thread]
    xor esi, esi
    lea rdx, [rip+worker]
    lea rcx, [rip+state]
    call [rip+slot_pthread_create]
    test eax, eax
    jnz fail_thread
wait_ready:
    cmp dword ptr [rip+state], 0
    jne close_handle
    call [rip+slot_sched_yield]
    jmp wait_ready
close_handle:
.if !KEEP_OPEN
    mov rdi, [rip+handle]
    call [rip+slot_dlclose]
    test eax, eax
    jnz fail_close
.endif
    cmp dword ptr [rip+state+8], 0
    jne fail_premature
.if LOCAL_PARENT && !KEEP_OPEN
    cmp dword ptr [rip+state+48], 1
    jne fail_parent
.endif
    mov dword ptr [rip+state+4], 1
    mov rdi, [rip+thread]
    xor esi, esi
    call [rip+slot_pthread_join]
    test eax, eax
    jnz fail_thread
    cmp dword ptr [rip+state+28], 0
    jne fail_register
    cmp dword ptr [rip+state+12], EXPECTED_CALLS
    jne fail_order
    cmp dword ptr [rip+state+64], 2
    jne fail_order
    cmp dword ptr [rip+state+68], 3
    jne fail_order
    lea rsi, [rip+state+72]
    mov ecx, REGISTRATIONS
check_ones:
    cmp dword ptr [rsi], 1
    jne fail_order
    add rsi, 4
    dec ecx
    jnz check_ones
.if FINI_REGISTER
    cmp dword ptr [rsi], 4
    jne fail_order
.endif
.if KEEP_OPEN
    mov rdi, [rip+handle]
    call [rip+slot_dlclose]
    test eax, eax
    jnz fail_close
.endif
.if FINI_REOPEN
    mov rdi, [rip+state+40]
    test rdi, rdi
    jz fail_reopen
    lea rsi, [rip+probe_symbol]
    call [rip+slot_dlsym]
    test rax, rax
    jz fail_reopen
    call rax
    cmp eax, 0x12345678
    jne fail_reopen
    mov rdi, [rip+state+40]
    call [rip+slot_dlclose]
    test eax, eax
    jnz fail_close
.endif
    cmp dword ptr [rip+state+8], 1
    je unloaded
    # glibc may postpone the final unload until another dlclose.
    lea rdi, [rip+library]
    mov esi, 6
    call [rip+slot_dlopen]
    test rax, rax
    jz fail_finalize
    mov rdi, rax
    call [rip+slot_dlclose]
    test eax, eax
    jnz fail_close
    cmp dword ptr [rip+state+8], 1
    jne fail_finalize
unloaded:
.if LOCAL_PARENT
    cmp dword ptr [rip+state+48], 1
    jne fail_parent
    cmp dword ptr [rip+state+36], 1
    jne fail_parent
.endif
.if USE_DEPENDENCY
    cmp dword ptr [rip+state+32], 1
    jne fail_dependency
.endif
    dec r12d
    jnz again
    xor edi, edi
    jmp finish
fail_open: mov edi, 2; jmp finish
fail_symbol: mov edi, 3; jmp finish
fail_thread: mov edi, 4; jmp finish
fail_close: mov edi, 5; jmp finish
fail_register: mov edi, 6; jmp finish
fail_order: mov edi, 7; jmp finish
fail_finalize: mov edi, 8; jmp finish
fail_reopen: mov edi, 9; jmp finish
fail_premature: mov edi, 10; jmp finish
fail_dependency: mov edi, 11; jmp finish
fail_parent: mov edi, 12
finish:
    mov eax, 231
    syscall
worker:
    push rbx
    mov rbx, rdi
    call [rip+registrar]
    test eax, eax
    jz ready
    mov dword ptr [rbx+28], 1
ready:
    mov dword ptr [rbx], 1
wait_exit:
    cmp dword ptr [rbx+4], 0
    jne exit_worker
    call [rip+slot_sched_yield]
    jmp wait_exit
exit_worker:
    xor eax, eax
    pop rbx
    ret
.org 0x1000
slot_dlopen: .quad 0
slot_dlsym: .quad 0
slot_dlclose: .quad 0
slot_pthread_create: .quad 0
slot_pthread_join: .quad 0
slot_sched_yield: .quad 0
handle: .quad 0
thread: .quad 0
registrar: .quad 0
.balign 64
state: .zero 3072
symbol: .asciz "register_destructors"
probe_symbol: .asciz "probe"
library: .asciz "LIBRARY"
""".replace("LIBRARY", str(library)).replace("ROUNDS", str(args.rounds)).replace(
        "KEEP_OPEN", str(int(args.keep_open))).replace("REGISTRATIONS", str(args.registrations)).replace(
        "EXPECTED_CALLS", str(args.registrations + 2 + int(args.fini_register))).replace(
        "FINI_REGISTER", str(int(args.fini_register))).replace("FINI_REOPEN", str(int(args.fini_reopen))).replace(
        "USE_DEPENDENCY", str(int(args.dependency))).replace("LOCAL_PARENT", str(int(args.local_parent)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", default="build/box64-cs2-repair")
    parser.add_argument("--rounds", type=int, default=16)
    parser.add_argument("--interpreter", action="store_true")
    parser.add_argument("--keep-open", action="store_true", help="control: retain the caller's handle until after thread exit")
    parser.add_argument("--registrations", type=int, default=1, help="number of initial repeated destructors, 1..512")
    parser.add_argument("--dependency", action="store_true", help="destructors call another DSO that must remain loaded")
    parser.add_argument("--fini-register", action="store_true", help="DT_FINI registers another TLS destructor")
    parser.add_argument("--fini-reopen", action="store_true", help="DT_FINI reopens its own DSO")
    parser.add_argument("--local-parent", action="store_true", help="close local parent before dependency TLS/FINI resolve lazy calls")
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("rounds must be positive")
    if not 1 <= args.registrations <= 512:
        parser.error("registrations must be between 1 and 512")
    if args.keep_open and (args.fini_register or args.fini_reopen):
        parser.error("DT_FINI reentrancy tests require close-before-worker-exit")
    if args.local_parent:
        if args.fini_reopen:
            parser.error("local-parent and fini-reopen are separate cases")
        args.dependency = True
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = {key: value for key, value in os.environ.items() if not key.startswith("BOX64_")}
    env.update(BOX64_NORCFILES="1", BOX64_NOBANNER="1", BOX64_LOG="0", BOX64_DYNACACHE="0",
               BOX64_DYNAREC_STRONGMEM="4", BOX64_DYNAREC_NOHOSTEXT="uscat", BOX64_SHOWSEGV="0")
    if args.interpreter:
        env["BOX64_DYNAREC"] = "0"
    with tempfile.TemporaryDirectory(prefix="box64-tls-cleanup-") as directory:
        directory = Path(directory)
        dependencies, imports = [], ["__cxa_thread_atexit_impl"]
        if args.dependency:
            dependencies.append(str(elf(directory, "libtls_cleanup_dependency.so", DEPENDENCY,
                                        [], ["record_event", "finalize_event"], shared=True, fini="finalize")))
            if not args.local_parent:
                imports.append("record_event")
        if args.fini_reopen:
            imports.append("dlopen")
        assembly = DSO.replace("REGISTRATIONS", str(args.registrations)).replace(
            "USE_DEPENDENCY", str(int(args.dependency))).replace("FINI_REGISTER", str(int(args.fini_register))).replace(
            "FINI_REOPEN", str(int(args.fini_reopen))).replace("SELF_LIBRARY", str(directory / "libtls_cleanup_fixture.so")).replace(
            "LOCAL_PARENT", str(int(args.local_parent)))
        library = elf(directory, "libtls_cleanup_fixture.so", assembly,
                      imports, ["register_destructors", "probe"], shared=True, fini="finalize", dependencies=dependencies,
                      lazy=("record_event", "finalize_event") if args.local_parent else ())
        if args.local_parent:
            library = elf(directory, "libtls_cleanup_parent.so", PARENT,
                          ["register_destructors"], ["parent_register"], shared=True, fini="finalize", dependencies=[str(library)])
        main = main_source(library, args)
        if args.local_parent:
            main = main.replace('symbol: .asciz "register_destructors"', 'symbol: .asciz "parent_register"')
            main = main.replace("mov esi, 2\n", "mov esi, 1\n")
        guest = elf(directory, "thread-cleanup", main,
                    ["dlopen", "dlsym", "dlclose", "pthread_create", "pthread_join", "sched_yield"])
        result = subprocess.run([str(Path(args.binary).resolve()), str(guest)],
                                env=env, capture_output=True, text=True, timeout=20)
    errors = {2: "dlopen failed", 3: "dlsym failed", 4: "pthread create/join failed", 5: "dlclose failed",
              6: "destructor registration failed", 7: "destructors missing or not LIFO (expected 2,3,1)",
              8: "DSO did not finalize after its final destructor", 9: "DSO reopened in DT_FINI was unloaded",
              10: "DSO finalized before worker destructors", 11: "dependency did not finalize after the last callback",
              12: "parent or late dependency finalizer did not run exactly once"}
    if result.returncode:
        print(f"FAIL: {errors.get(result.returncode, 'unexpected process failure')}; exit={result.returncode}")
        print((result.stdout + result.stderr)[-2000:])
        return 1
    print(f"PASS: {args.rounds} dlclose/thread-exit cycles; registrations={args.registrations}, "
          f"dependency={args.dependency}, fini_register={args.fini_register}, "
          f"fini_reopen={args.fini_reopen}, keep_open={args.keep_open}, local_parent={args.local_parent}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
