#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/box64-mapping-lifetime.XXXXXX")
trap 'rm -rf -- "$test_dir"' EXIT HUP INT TERM
cd "$repo_dir"
"${CC:-cc}" -O1 -g -fsanitize=address -fno-omit-frame-pointer \
    -ffunction-sections -fdata-sections -D_GNU_SOURCE -DARM64 -DDYNAREC -DSTATICBUILD \
    -DcustomMalloc=malloc -DcustomCalloc=calloc -DcustomRealloc=realloc \
    -DcustomFree=free -Dbox_strdup=strdup -Isrc -Isrc/include \
    tests/env_mapping_lifetime.c src/tools/rbtree.c \
    -Wl,--gc-sections -pthread -ldl -o "$test_dir/mapping-lifetime"
ASAN_OPTIONS=detect_leaks=0 timeout 15 "$test_dir/mapping-lifetime"
