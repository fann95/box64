#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/box64-cleanup.XXXXXX")
trap 'rm -rf -- "$test_dir"' EXIT HUP INT TERM
cd "$repo_dir"
"${CC:-cc}" -O1 -g -ffunction-sections -fdata-sections -D_GNU_SOURCE \
    -Isrc -Isrc/include tests/cleanup_threads.c \
    -Wl,--gc-sections -pthread -o "$test_dir/cleanup-threads"
timeout 20 "$test_dir/cleanup-threads"
