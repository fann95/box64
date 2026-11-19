// SPDX-License-Identifier: MIT
#include <assert.h>
#include "custommem.c"

box64env_t box64env;
uintptr_t box64_pagesize = 4096;
int box64_is32bits;
extern void* my_mremap(x64emu_t*, void*, size_t, size_t, int, void*);

void enter_critical_section(void) {}
void leave_critical_section(void) {}
void PrintfFtrace(int prefix, const char* format, ...) {}

static int resize_mapping(size_t old_size, size_t new_size)
{
    const size_t page = box64_pagesize;
    unsigned char* base = mmap(NULL, 4 * page, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(base != MAP_FAILED);
    size_t old_pages = ALIGN(old_size) / page;
    size_t new_pages = ALIGN(new_size) / page;
    // Reserve the last page so growth cannot absorb a neighbouring VMA.
    assert(mprotect(base + 3 * page, page, PROT_NONE) == 0);
    if (old_pages < 3) assert(munmap(base + old_pages * page, (3 - old_pages) * page) == 0);
    setProtection_mmap((uintptr_t)base, old_pages * page, PROT_READ | PROT_WRITE);
    assert(my_mremap(NULL, base, old_size, new_size, 0, NULL) == base);
    int failures = 0;
    for (size_t i = 0; i < 3; ++i) {
        unsigned char resident;
        int mapped = mincore(base + i * page, page, &resident) == 0;
        assert(mapped == (i < new_pages));
        int tracked = !!getProtection((uintptr_t)base + i * page);
        if (tracked != mapped) {
            fprintf(stderr, "FAIL: mremap %zu -> %zu, page %zu: kernel=%d, Box64=%d\n",
                    old_size, new_size, i, mapped, tracked);
            ++failures;
        }
    }
    freeProtection((uintptr_t)base, 4 * page);
    assert(munmap(base, 4 * page) == 0);
    return failures;
}

int main(void)
{
    init_mutexes();
    memprot = rbtree_init("test permissions");
    mapallmem = rbtree_init("test mappings");
    const size_t cases[][2] = {
        {4096, 1}, {8192, 4097}, {8192, 4095}, {12288, 4097},
        {4095, 4097}, {4097, 12287}, {4097, 8191}, {8192, 4096},
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        failures += resize_mapping(cases[i][0], cases[i][1]);
    rbtree_delete(memprot);
    rbtree_delete(mapallmem);
    if (!failures) puts("PASS: mremap page tracking matches kernel for aligned and partial-page resizes");
    return failures ? 1 : 0;
}
