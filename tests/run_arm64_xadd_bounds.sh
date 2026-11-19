#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/box64-xadd-bounds.XXXXXX")
trap 'rm -rf -- "$test_dir"' EXIT HUP INT TERM
cd "$repo_dir"
"${CC:-cc}" -O2 -g -march=armv8.1-a+crc -DARM64 -pthread -Isrc -Isrc/include \
    tests/arm64_xadd_bounds.c src/dynarec/arm64/arm64_lock.S -o "$test_dir/xadd-bounds"
"$test_dir/xadd-bounds"
