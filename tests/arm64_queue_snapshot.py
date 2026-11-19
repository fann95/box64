# SPDX-License-Identifier: MIT
"""Check x86 load ordering while a tagged queue head is published and reused.

The writer atomically publishes {node, generation} using aligned CMPXCHG16B,
then clears the retired node. A reader takes generation, node, node->value,
and generation again, like CS2's queue validation loop. On x86 a snapshot
whose generation agrees must not contain a cleared retired node. The two nodes
are permanent allocations; the test never dereferences freed memory.

The writer drains its clear and delays briefly so the retired state remains
observable instead of being coalesced with immediate reuse. --reordered is an
intentionally invalid negative control and should report failures, even at level 4.
This is a bounded concurrency experiment, not a deterministic proof of absence.
"""
import argparse
import os
from pathlib import Path
import resource
import struct
import subprocess
import tempfile

from arm64_unaligned_atomics import make_guest as make_pthread_guest
from arm64_xadd_state import text_section


def make_guest(directory, iterations, readers, fence, reordered):
    guest = directory / "queue-snapshot"
    make_pthread_guest(guest, 0)
    data = 0x402000
    pair, node_a, node_b = data + 0xA00, data + 0xB00, data + 0xB80
    start, stop, output = data + 0x900, data + 0x940, data + 0xC00
    lines = [".intel_syntax noprefix", ".text"]
    for i in range(readers + 1):
        lines += [f"mov edi, {data + 0x800 + i * 8}", "xor esi, esi",
                  f"lea rdx, [rip+{'writer' if i == 0 else 'reader'}]",
                  f"mov ecx, {output + (i - 1) * 24 if i else 0}",
                  f"call qword ptr [{data}]", "test eax,eax", "jnz failed"]
    lines += [f"mov dword ptr [{start}], 1"]
    for i in range(readers + 1):
        lines += [f"mov rdi, qword ptr [{data + 0x800 + i * 8}]", "xor esi,esi",
                  f"call qword ptr [{data + 8}]", "test eax,eax", "jnz failed"]
    lines += ["mov eax,1", "mov edi,1", f"mov esi,{output}", f"mov edx,{readers * 24}",
              "syscall", "xor edi,edi", "mov eax,60", "syscall",
              "failed:", "mov edi,2", "mov eax,60", "syscall",
              "writer:", "push rbx", "push r12", f"mov r12d,{iterations}",
              f"mov edi,{pair}", f"mov eax,{node_a}", "xor edx,edx", f"mov r10d,{node_b}",
              "writer_wait:", f"cmp dword ptr [{start}],0", "je writer_wait",
              "writer_loop:", "mov qword ptr [r10],1", "mov r11,rax", "mov rbx,r10",
              "lea rcx,[rdx+1]", "lock cmpxchg16b [rdi]", "jne failed",
              "mov qword ptr [r11],0", "mfence", "mov esi,64", "writer_delay:", "dec esi",
              "jnz writer_delay", "mov rax,r10", "mov rdx,rcx", "mov r10,r11",
              "dec r12d", "jnz writer_loop", f"mov dword ptr [{stop}],1",
              "pop r12", "pop rbx", "xor eax,eax", "ret",
              "reader:", "push rbx", "push r12", "push r13", "push r14",
              "mov r14,rdi", "xor r12d,r12d", "xor r13d,r13d", "xor ebx,ebx",
              f"mov edi,{pair}", "reader_wait:", f"cmp dword ptr [{start}],0", "je reader_wait",
              "reader_loop:", "mov r8,[rdi+8]"]
    if fence:
        lines += ["lfence"]
    lines += ["mov r9,[rdi]"]
    if not reordered:
        lines += ["mov r10,[r9]"]
    if fence:
        lines += ["lfence"]
    lines += ["mov r11,[rdi+8]"]
    if reordered:
        lines += ["mov esi,64", "reader_delay:", "dec esi", "jnz reader_delay", "mov r10,[r9]"]
    lines += ["cmp r8,r11", "jne reader_retry", "inc r12",
              "test r10,r10", "jnz reader_next", "inc r13", "jmp reader_next",
              "reader_retry:", "inc rbx", "reader_next:", f"cmp dword ptr [{stop}],0",
              "je reader_loop", "mov [r14],r12", "mov [r14+8],rbx", "mov [r14+16],r13",
              "pop r14", "pop r13", "pop r12", "pop rbx", "xor eax,eax", "ret"]
    source, obj = directory / "queue.S", directory / "queue.o"
    source.write_text("\n".join(lines) + "\n")
    subprocess.run(["clang", "-target", "x86_64-linux-gnu", "-c", str(source), "-o", str(obj)], check=True)
    code = text_section(obj.read_bytes())
    assert len(code) < 0xE00
    image = bytearray(guest.read_bytes())
    image[0x200:0x1000] = bytes(0xE00)
    image[0x200:0x200 + len(code)] = code
    struct.pack_into("<QQ", image, 0x1000 + pair - data, node_a, 0)
    struct.pack_into("<Q", image, 0x1000 + node_a - data, 1)
    guest.write_bytes(image)
    return guest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", default="build/box64-jit-lifetime")
    parser.add_argument("--iterations", type=int, default=3000000)
    parser.add_argument("--readers", type=int, default=3)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--levels", default="3,4")
    parser.add_argument("--fence", action="store_true", help="add guest LFENCE around dependent read")
    parser.add_argument("--reordered", action="store_true", help="negative control: read the node after both generations")
    args = parser.parse_args()
    if not 1 <= args.iterations <= 0xFFFFFFFF or args.rounds < 1:
        parser.error("iterations must fit a positive 32-bit count and rounds must be positive")
    if not 1 <= args.readers <= 8:
        parser.error("readers must be between 1 and 8")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = {key: value for key, value in os.environ.items() if not key.startswith("BOX64_")}
    env.update(BOX64_NORCFILES="1", BOX64_NOBANNER="1", BOX64_LOG="0", BOX64_DYNACACHE="0",
               BOX64_DYNAREC_NOHOSTEXT="uscat", BOX64_SHOWSEGV="0")
    binary = Path(args.binary).resolve()
    failures = 0
    with tempfile.TemporaryDirectory(prefix="box64-queue-snapshot-") as directory:
        guest = make_guest(Path(directory), args.iterations, args.readers, args.fence, args.reordered)
        for level in args.levels.split(","):
            env["BOX64_DYNAREC_STRONGMEM"] = level
            for run in range(args.rounds):
                result = subprocess.run([str(binary), str(guest)], env=env, capture_output=True, timeout=45)
                if result.returncode or len(result.stdout) != args.readers * 24:
                    print(f"ERROR: level={level} exit={result.returncode} stdout={result.stdout!r} stderr={result.stderr[-500:]!r}")
                    return 2
                counts = list(struct.iter_unpack("<QQQ", result.stdout))
                total = tuple(sum(row[i] for row in counts) for i in range(3))
                failures += bool(total[2])
                print(f"{'FAIL' if total[2] else 'PASS'}: binary={binary.name} STRONGMEM={level} "
                      f"round={run+1} lfence={args.fence} reordered={args.reordered} accepted={total[0]} retried={total[1]} "
                      f"invalid_snapshots={total[2]}", flush=True)
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
