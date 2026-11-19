#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/box32-fdelt.XXXXXX")
trap 'rm -rf -- "$test_dir"' EXIT HUP INT TERM

cd "$repo_dir"
"${CC:-cc}" -O1 -g -ffunction-sections -fdata-sections \
    -D_GNU_SOURCE -DBOX32 \
    -Isrc -Isrc/include -Isrc/wrapped/generated -Isrc/wrapped32/generated \
    -Wno-address-of-packed-member \
    tests/box32_fdelt.c src/wrapped32/wrappedlibc.c \
    -Wl,--gc-sections -pthread -ldl -o "$test_dir/box32-fdelt"

"$test_dir/box32-fdelt"
