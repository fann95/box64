#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/box32-freetype-bitmap.XXXXXX")
trap 'rm -rf -- "$test_dir"' EXIT HUP INT TERM

cd "$repo_dir"
"${CC:-cc}" -O1 -g -ffunction-sections -fdata-sections \
    -D_GNU_SOURCE -DBOX32 \
    -Isrc -Isrc/include -Isrc/wrapped/generated -Isrc/wrapped32/generated \
    tests/box32_freetype_bitmap.c src/wrapped32/generated/wrapper32.c \
    src/wrapped32/generated/converter32.c \
    -Wl,--gc-sections -pthread -ldl -o "$test_dir/box32-freetype-bitmap"

"$test_dir/box32-freetype-bitmap"
