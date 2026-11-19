# SPDX-License-Identifier: MIT
"""Check that x86-64 pthread_once waiters see completed initialization."""

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
    xor r14d, r14d
    xor r15d, r15d
    lea rdi, [rip+worker_id]
    xor esi, esi
    lea rdx, [rip+worker]
    xor ecx, ecx
    call [rip+slot_pthread_create]
    test eax, eax
    jnz failed_create
await_started:
    cmp dword ptr [rip+started], 1
    je wait_once
    mov edi, 1000
    call [rip+slot_usleep]
    jmp await_started
wait_once:
    mov r13d, MODE
    cmp r13d, 1
    je cancel_worker
    cmp r13d, 2
    je join_before_retry
    cmp r13d, 3
    je fork_while_initializing
    jmp call_once
cancel_worker:
    mov rdi, [rip+worker_id]
    call [rip+slot_pthread_cancel]
    test eax, eax
    jnz failed_cancel
join_before_retry:
    mov rdi, [rip+worker_id]
    lea rsi, [rip+worker_result]
    call [rip+slot_pthread_join]
    test eax, eax
    jnz failed_join
    mov r14d, 1
    mov rax, -1
    cmp r13d, 1
    je check_worker_result
    mov eax, 0x777
check_worker_result:
    cmp [rip+worker_result], rax
    jne failed_worker_result
    jmp call_once
fork_while_initializing:
    call [rip+slot_fork]
    test eax, eax
    js failed_fork
    jz child
    mov r15d, eax
call_once:
    lea rdi, [rip+once]
    lea rsi, [rip+initialize]
    call [rip+slot_pthread_once]
    mov r12d, [rip+ready]
    test r14d, r14d
    jnz check_ready
    mov rdi, [rip+worker_id]
    xor esi, esi
    call [rip+slot_pthread_join]
    test eax, eax
    jnz failed_join
check_ready:
    cmp r12d, 0x12345678
    jne failed_early
    lea rdi, [rip+once]
    lea rsi, [rip+initialize]
    call [rip+slot_pthread_once]
    mov eax, 1
    add eax, r14d
    cmp dword ptr [rip+calls], eax
    jne failed_count
    cmp dword ptr [rip+nested_calls], 1
    jne failed_nested
    test r15d, r15d
    jz success
    mov edi, r15d
    lea rsi, [rip+child_status]
    xor edx, edx
    call [rip+slot_waitpid]
    cmp eax, r15d
    jne failed_child
    cmp dword ptr [rip+child_status], 0
    jne failed_child
success:
    xor edi, edi
    jmp finish
failed_create: mov edi, 1; jmp finish
failed_join: mov edi, 2; jmp finish
failed_early: mov edi, 3; jmp finish
failed_count: mov edi, 4; jmp finish
failed_nested: mov edi, 5; jmp finish
failed_cancel: mov edi, 6; jmp finish
failed_worker_result: mov edi, 7; jmp finish
failed_fork: mov edi, 8; jmp finish
failed_child: mov edi, 9
finish:
    mov eax, 231
    syscall
child:
    lea rdi, [rip+once]
    lea rsi, [rip+initialize]
    call [rip+slot_pthread_once]
    cmp dword ptr [rip+ready], 0x12345678
    jne failed_early
    cmp dword ptr [rip+calls], 2
    jne failed_count
    jmp success
worker:
    sub rsp, 8
    lea rdi, [rip+once]
    lea rsi, [rip+initialize]
    call [rip+slot_pthread_once]
    add rsp, 8
    xor eax, eax
    ret
initialize:
    sub rsp, 8
    add dword ptr [rip+calls], 1
    mov dword ptr [rip+started], 1
    mov eax, MODE
    cmp eax, 2
    jne initialize_data
    cmp dword ptr [rip+calls], 1
    jne initialize_data
    mov edi, 0x777
    call [rip+slot_pthread_exit]
initialize_data:
    mov edi, 200000
    call [rip+slot_usleep]
    lea rdi, [rip+nested_once]
    lea rsi, [rip+initialize_nested]
    call [rip+slot_pthread_once]
    mov dword ptr [rip+ready], 0x12345678
    add rsp, 8
    ret
initialize_nested:
    add dword ptr [rip+nested_calls], 1
    ret
.org 0x1000
slot_pthread_create: .quad 0
slot_pthread_join: .quad 0
slot_pthread_once: .quad 0
slot_usleep: .quad 0
slot_pthread_cancel: .quad 0
slot_pthread_exit: .quad 0
slot_fork: .quad 0
slot_waitpid: .quad 0
worker_id: .quad 0
worker_result: .quad 0
child_status: .long 0
once: .long 0
nested_once: .long 0
started: .long 0
ready: .long 0
calls: .long 0
nested_calls: .long 0
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("box64", type=Path)
    parser.add_argument("--interpreter", action="store_true")
    parser.add_argument("--mode", choices=("completion", "cancel", "exit", "fork"), default="completion")
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    environment = {k: v for k, v in os.environ.items() if not k.startswith("BOX64_")}
    environment.update(BOX64_NORCFILES="1", BOX64_LOG="0", BOX64_NOBANNER="1",
                       BOX64_DYNACACHE="0", BOX64_DYNAREC_STRONGMEM="4",
                       BOX64_DYNAREC="0" if args.interpreter else "1")
    with tempfile.TemporaryDirectory(prefix="box64-once-completion-") as directory:
        mode = ("completion", "cancel", "exit", "fork").index(args.mode)
        guest = elf(Path(directory), "once-completion", SOURCE.replace("MODE", str(mode)),
                    ["pthread_create", "pthread_join", "pthread_once", "usleep",
                     "pthread_cancel", "pthread_exit", "fork", "waitpid"])
        result = subprocess.run([str(args.box64.resolve()), str(guest)], env=environment,
                                capture_output=True, text=True, timeout=10)
    failures = {1: "pthread_create", 2: "pthread_join", 3: "waiter returned before initialization",
                4: "wrong initialization count", 5: "nested once initialization",
                6: "pthread_cancel", 7: "thread exit result", 8: "fork", 9: "child initialization"}
    if result.returncode:
        print("FAIL:", failures.get(result.returncode, f"process exit {result.returncode}"))
        print((result.stdout + result.stderr)[-2000:])
        return 1
    print(f"PASS ({args.mode}): completed initialization, correct call count and nested once")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
