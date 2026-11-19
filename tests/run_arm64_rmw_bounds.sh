#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
ulimit -c 0
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/box64-rmw-bounds.XXXXXX")
trap 'rm -rf -- "$test_dir"' EXIT HUP INT TERM
cd "$repo_dir"
"${CC:-cc}" -O2 -g -march=armv8.1-a+crc -DARM64 -pthread -Isrc -Isrc/include \
    tests/arm64_rmw_bounds.c src/dynarec/arm64/arm64_lock.S -o "$test_dir/rmw-bounds"
"$test_dir/rmw-bounds"
