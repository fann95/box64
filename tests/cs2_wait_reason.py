#!/usr/bin/env python3
"""Read short snapshots of an existing CS2 wait; no ptrace, signals or writes to it."""
import argparse
import bisect
import collections
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

from cs2_perf_snapshot import find_game, identity, checked_identity
from cs2_jit_profile import parse_maps

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_BINARY = ROOT / "build/box64-cs2-profile-fixed"
EXPECTED_HASH = "4c4aafd57d4f669d026c1fbc167af0df320dbb80d2dbc6ffc9e869835b481dde"
# DWARF offsets from precisely the above executable; refuse any other build.
CONTEXT_POINTER = 0x363fbcf8
EMU_CONTEXT, EMU_IP, EMU_RSP, EMU_RBP = 1200, 136, 32, 40


def collect(pid, expected):
    checked_identity(pid, expected)
    if Path(expected[2]) != EXPECTED_BINARY:
        raise RuntimeError("Ожидалась текущая диагностическая сборка Box64.")
    with EXPECTED_BINARY.open("rb") as binary:
        if hashlib.file_digest(binary, "sha256").hexdigest() != EXPECTED_HASH:
            raise RuntimeError("Сборка изменилась; смещения отладочных структур нужно проверить заново.")
    proc = Path(f"/proc/{pid}")
    maps_text = (proc / "maps").read_text()
    maps, errors = parse_maps(maps_text)
    if errors:
        raise RuntimeError(str(errors))
    starts = [m.start for m in maps]

    def mapping(addr):
        index = bisect.bisect_right(starts, addr) - 1
        return maps[index] if index >= 0 and addr < maps[index].end else None

    with (proc / "mem").open("rb", buffering=0) as memory:
        def read(addr, size):
            m = mapping(addr)
            if not m or "r" not in m.permissions or not 0 < size <= 4096:
                return b""
            try:
                return os.pread(memory.fileno(), min(size, m.end - addr), addr)
            except OSError:
                return b""

        context = read(CONTEXT_POINTER, 8)
        if len(context) != 8:
            raise RuntimeError("Не удалось прочитать контекст проверенной сборки.")
        samples, contexts, known = [], [], {}
        start = time.monotonic()
        for _ in range(200):
            if time.monotonic() - start >= 3:
                break
            raw = (proc / "syscall").read_text().strip()
            sample = {"time_ns": time.monotonic_ns(), "syscall": raw}
            fields = raw.split()
            if len(fields) == 9 and fields[0] != "-1":
                nr, *values = [int(f, 0) for f in fields]
                args, sp, pc = values[:6], values[6], values[7]
                key = (nr, *args, sp, pc)
                if key not in known and len(contexts) < 64:
                    row = {"number": nr, "args": args, "sp": sp, "pc": pc, "emulators": []}
                    stack = read(sp, 4096)
                    row["native_stack_hex"] = stack.hex()
                    candidates = set(struct.unpack_from("<Q", stack, n)[0]
                                     for n in range(0, len(stack) - 7, 8))
                    for address in candidates:
                        if address & 7 or read(address + EMU_CONTEXT, 8) != context:
                            continue
                        regs = read(address, EMU_IP + 8)
                        if len(regs) < EMU_IP + 8:
                            continue
                        rsp, rbp = struct.unpack_from("<QQ", regs, EMU_RSP)
                        ip = struct.unpack_from("<Q", regs, EMU_IP)[0]
                        gm = mapping(rsp)
                        if not gm or "w" not in gm.permissions:
                            continue
                        row["emulators"].append({"address": address, "ip": ip, "rsp": rsp, "rbp": rbp,
                                                  "guest_stack_hex": read(rsp, 2048).hex()})
                    timeout = args[3] if nr == 98 and args[1] & 127 in (0, 9, 11) else (
                        args[0] if nr == 101 else args[2] if nr in (73, 115) else 0)
                    if timeout:
                        data = read(timeout, 16)
                        if len(data) == 16:
                            row["timespec"] = list(struct.unpack("<qq", data))
                    if nr == 98:
                        data = read(args[0], 4)
                        if len(data) == 4:
                            row["futex_value"] = struct.unpack("<I", data)[0]
                    if nr in (22, 29, 63, 64, 441):
                        try:
                            row["fd_target"] = os.readlink(proc / "fd" / str(args[0]))
                            row["fdinfo"] = (proc / "fdinfo" / str(args[0])).read_text()[:4096]
                        except OSError:
                            pass
                    row["syscall_unchanged_during_read"] = (proc / "syscall").read_text().strip() == raw
                    known[key] = len(contexts)
                    contexts.append(row)
                sample["context"] = known.get(key)
            samples.append(sample)
            time.sleep(0.01)
    checked_identity(pid, expected)
    return {"pid": pid, "identity": expected, "duration": time.monotonic() - start,
            "non_atomic_read_only_snapshots": True, "samples": samples, "contexts": contexts,
            "maps_before": maps_text, "maps_after": (proc / "maps").read_text()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collect", type=int)
    parser.add_argument("--identity")
    args = parser.parse_args()
    if args.collect is not None:
        print(json.dumps(collect(args.collect, tuple(json.loads(args.identity)))))
        return
    if os.getuid() == 0:
        raise RuntimeError("Запусти помощник без sudo; он запросит пароль сам.")
    pid = find_game()
    expected = identity(pid)
    subprocess.run(["sudo", "-v"], check=True)
    print("Вернись в матч. Через 10 секунд — чтение ожиданий на 2–3 секунды. Игра не останавливается.", flush=True)
    time.sleep(10)
    checked_identity(pid, expected)
    result = subprocess.run(["sudo", "-n", "timeout", "8s", sys.executable, str(Path(__file__).resolve()),
                             "--collect", str(pid), "--identity", json.dumps(expected)],
                            capture_output=True, text=True, timeout=12)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"collector exit {result.returncode}")
    data = json.loads(result.stdout)
    output = ROOT / "build/cs2-profile/detailed/slow.wait-reason.json"
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(f"ГОТОВО: {output}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(f"Ошибка: {error}")
