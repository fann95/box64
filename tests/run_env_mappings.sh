#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/box64-env-mappings.XXXXXX")
trap 'rm -rf -- "$test_dir"' EXIT HUP INT TERM
cd "$repo_dir"
"${CC:-cc}" -O1 -g -ffunction-sections -fdata-sections -D_GNU_SOURCE -DARM64 \
    -DcustomMalloc=malloc -DcustomFree=free -Isrc/include \
    -c src/tools/rbtree.c -o "$test_dir/rbtree.o"
"${CC:-cc}" -O1 -g -ffunction-sections -fdata-sections -D_GNU_SOURCE -DARM64 \
    -DcustomMalloc=malloc -DcustomCalloc=calloc -DcustomRealloc=realloc \
    -DcustomFree=free -Dbox_strdup=strdup \
    -Isrc -Isrc/include tests/env_mappings.c "$test_dir/rbtree.o" \
    -Wl,--gc-sections -pthread -ldl -o "$test_dir/env-mappings"
timeout 15 "$test_dir/env-mappings"
