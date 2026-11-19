# SPDX-License-Identifier: MIT
"""Check RMW helper CALL state, source aliases, compare success and live carry.

Each guest retains all GPRs, sixteen AVX registers and an x87 value across an
unaligned RMW. Native carry is produced by both CMP (inverted) and ADD (normal).
Usage: python3 -B tests/arm64_rmw_state.py [build/box64] [--quick]
"""
import argparse
from collections import Counter
import os
from pathlib import Path
import resource
import subprocess
import tempfile

from arm64_xadd_state import make_guest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", default="build/box64")
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    binary = Path(args.binary).resolve()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = {key: value for key, value in os.environ.items() if not key.startswith("BOX64_")}
    env.update(BOX64_NORCFILES="1", BOX64_NOBANNER="1", BOX64_LOG="0", BOX64_SHOWSEGV="0",
               BOX64_DYNACACHE="0", BOX64_DYNAREC_STRONGMEM="3")
    features = ("uscat", "atomics") if args.quick else ("uscat", "", "atomics", "uscat,atomics")
    sources = ("rax", "rdi") if args.quick else ("rax", "rdi", "r8", "r15")
    totals, failures, examples = Counter(), Counter(), []
    with tempfile.TemporaryDirectory(prefix="box64-rmw-state-") as directory:
        for operation in ("add", "adc", "and", "or", "cmpxchg", "xchg", "sub", "xor", "lock_xchg"):
            for width in ((32, 64) if operation in ("sub", "xor", "lock_xchg") else (16, 32, 64)):
                for source in sources:
                    for position in (0x801, 0x807):
                        for matches in ((False, True) if operation == "cmpxchg" else (False,)):
                            carries = ("cmp0", "cmp1", "add0", "add1") if operation == "adc" else ("push1",)
                            for carry in carries:
                                guest, expected = make_guest(Path(directory), source, width, operation,
                                                             position, matches, carry)
                                for disabled in features:
                                    env["BOX64_DYNAREC_NOHOSTEXT"] = disabled
                                    group = f"{operation}{width}"
                                    label = (f"{group} source={source} offset={position & 15} "
                                             f"match={matches} flags={carry} NOHOSTEXT={disabled or 'none'}")
                                    totals[group] += 1
                                    try:
                                        result = subprocess.run([str(binary), str(guest)], env=env,
                                                                capture_output=True, timeout=5)
                                        passed = result.returncode == 0 and result.stdout == expected
                                        detail = f"exit={result.returncode}, bytes={len(result.stdout)}/{len(expected)}"
                                        if result.returncode == 0 and len(result.stdout) == len(expected) and not passed:
                                            byte = next(i for i, pair in enumerate(zip(result.stdout, expected)) if pair[0] != pair[1])
                                            detail += f", byte={byte:#x}, got={result.stdout[byte]:02x}, expected={expected[byte]:02x}"
                                    except subprocess.TimeoutExpired:
                                        passed, detail = False, "timeout"
                                    if not passed:
                                        failures[group] += 1
                                        if len(examples) < 16:
                                            examples.append(f"{label}: {detail}")
    for group in totals:
        print(f"{'FAIL' if failures[group] else 'PASS'}: {group}: {totals[group] - failures[group]}/{totals[group]}")
    for example in examples:
        print("  " + example)
    print(f"TOTAL: {sum(totals.values()) - sum(failures.values())}/{sum(totals.values())} passed")
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
