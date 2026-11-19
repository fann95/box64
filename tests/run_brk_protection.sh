#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/box64-brk-protection.XXXXXX")
trap 'rm -rf -- "$test_dir"' EXIT HUP INT TERM
cd "$repo_dir"

"${CC:-cc}" -O1 -g -ffunction-sections -fdata-sections -D_GNU_SOURCE \
    -DcustomMalloc=malloc -DcustomFree=free -Isrc/include \
    -c src/tools/rbtree.c -o "$test_dir/rbtree.o"
"${CC:-cc}" -O1 -g -ffunction-sections -fdata-sections -D_GNU_SOURCE \
    -Isrc -Isrc/include -Isrc/wrapped/generated -Isrc/wrapped32/generated \
    tests/brk_protection.c "$test_dir/rbtree.o" \
    -Wl,--gc-sections -pthread -ldl -o "$test_dir/brk-protection"
"$test_dir/brk-protection"
