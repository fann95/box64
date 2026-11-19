# SPDX-License-Identifier: MIT
"""Compile the production journal writer and test without launching Box64."""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def body(source, start):
    opening = source.index("{", start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end] + "\n"


with tempfile.TemporaryDirectory(prefix="box64-jit-profile-") as temporary:
    temporary = Path(temporary)
    includes = temporary / "includes"
    includes.mkdir()
    (includes / "debug.h").write_text("#define BOX64ENV(name) (-1)\n")
    (includes / "box64context.h").write_text("")
    (includes / "elfloader.h").write_text(
        "static const char* getAddrFunctionName(uintptr_t addr) { return 0; }\n")
    binary = temporary / "metadata"
    subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
        "-std=gnu11", "-O1", "-g", "-DDYNAREC", "-pthread",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(includes), "-I", str(ROOT / "src/include"), "-I", str(ROOT / "src"),
        str(ROOT / "tests/jit_profile_metadata.c"), "-o", str(binary),
    ], check=True)
    modes = ("normal", "off", "exclusive", "symlink", "short", "failure",
             "reentrant", "invalid", "guest_bounds", "native_bounds", "unterminated",
             "cap", "fork", "threads", "dead_tail")
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = environment.get("ASAN_OPTIONS", "") + ":detect_leaks=0"
    for mode in modes:
        directory = temporary / mode
        directory.mkdir()
        subprocess.run([str(binary), mode, str(directory)], check=True, timeout=15, env=environment)
        logs = list(directory.glob("jit-*.maplog"))
        if mode == "off":
            assert not logs
            continue
        assert len(logs) == 1
        log = logs[0]
        if mode == "exclusive":
            assert log.read_text() == "keep"
            continue
        if mode == "symlink":
            assert log.is_symlink() and not log.exists()
            continue
        if mode == "cap":
            assert log.stat().st_size <= 128 * 1024 * 1024
            with log.open("rb") as stream:
                stream.seek(128 * 1024 * 1024 - 128 - 8)
                assert stream.read().decode().split("\t")[-1] == "limit\n"
            continue
        rows = [line.split("\t") for line in log.read_text().splitlines()]
        assert rows[0][:2] == ["V", "1"] and len(rows[0]) == 4
        assert log.stem == "jit-" + rows[0][2]
        stamps = [int(rows[0][3])] + [int(row[1]) for row in rows[1:]]
        assert stamps == sorted(stamps)
        if mode in ("failure", "reentrant", "invalid", "guest_bounds", "native_bounds", "unterminated"):
            expected = {"failure": "write", "reentrant": "reentrant"}.get(mode, "metadata")
            assert rows[-1][0] == "E" and rows[-1][2] == expected
            continue
        events = rows[1:]
        assert len(events) == (204 if mode == "threads" else 4)
        assert events[0][0] == "L" and events[-3][0] == "U"
        assert events[-2][0] == "L" and events[-1][0] == "U"
        assert events[0][2] == events[-2][2] == events[-1][2]
        assert events[0][4] == "400000" and events[-2][4] == "500000"
        for row in events:
            assert len(row) == (8 if row[0] == "L" else 4)
            assert row[3] == "50"
            if row[0] == "L":
                assert row[5:] == ["46" if mode == "dead_tail" else "14", "4", "24ff001100"]
    print(f"PASS: JIT journal format, errno, reuse, fork, contention, failures and cap ({len(modes)} cases)")
    source = (ROOT / "src/custommem.c").read_text()
    functions = ""
    for name in ("FindDynablockFromNativeAddress", "IsDynablockLive", "FreeDynarecMap"):
        match = re.search(r"^(?:dynablock_t\*|int|void) " + name + r"\(", source, re.M)
        assert match, name
        functions += body(source, match.start())
    chunk_guard = source.index("if(jitProfileActive())", source.index("void DelMmaplist("))
    functions += ("static void unload_chunk(blocklist_t* chunk) {\n"
                  "blocklist_t* chunks[] = {chunk}; mmaplist_t value = {chunks};\n"
                  "mmaplist_t* list = &value; int i = 0;\n" + body(source, chunk_guard) + "}\n")
    (temporary / "jit_profile_metadata_lifetime.inc").write_text(functions)
    lifetime = temporary / "lifetime"
    subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
        "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(temporary), "-I", str(ROOT / "src/dynarec"),
        str(ROOT / "tests/jit_profile_metadata_lifetime.c"), "-o", str(lifetime),
    ], check=True)
    subprocess.run([str(lifetime)], check=True, timeout=15, env=environment)
