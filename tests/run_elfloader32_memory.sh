#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/box32-elf-memory.XXXXXX")
trap 'rm -rf -- "$test_dir"' EXIT HUP INT TERM

cd "$repo_dir"
"${CC:-cc}" -O1 -g -ffunction-sections -fdata-sections \
    -D_GNU_SOURCE -DSTATICBUILD -DBOX32 \
    -Isrc -Isrc/include -Isrc/wrapped/generated -Isrc/wrapped32/generated \
    -Wno-address-of-packed-member \
    tests/elfloader32_memory.c src/elfs/elfloader32.c src/tools/rbtree.c \
    -Wl,--gc-sections -Wl,--wrap=mmap -Wl,--wrap=munmap -pthread \
    -o "$test_dir/elfloader32-memory"

ulimit -c 0
for scenario in normal gap hint collision failed exhausted high crossing fixed; do
    "$test_dir/elfloader32-memory" "$scenario"
done
