// SPDX-License-Identifier: MIT
#include <assert.h>
#include <stdarg.h>
#include "custommem.c"

box64env_t box64env;
uintptr_t box64_pagesize = 4096;

void enter_critical_section(void) {}
void leave_critical_section(void) {}
void PrintfFtrace(int prefix, const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

static void reset_tracking(uintptr_t base, uintptr_t previous)
{
    if (memprot) rbtree_delete(memprot);
    if (mapallmem) rbtree_delete(mapallmem);
    memprot = rbtree_init("test permissions");
    mapallmem = rbtree_init("test mappings");
    pbrk = base;
    old_brk = previous;
}

int main(void)
{
    init_mutexes();
    const size_t page = box64_pagesize;
    void* mapping = mmap(NULL, 8 * page, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(mapping != MAP_FAILED);
    uintptr_t base = (uintptr_t)mapping;
    uintptr_t current = base + 6 * page;
    cur_brk = &current;
    int failures = 0;
    for (int first = 0; first <= 1; ++first) {
        current = base + 6 * page;
        reset_tracking(base, first ? 0 : base + 2 * page);
        setProtection(base, 2 * page, PROT_READ | PROT_WRITE);
        assert(!mprotect((void*)(base + 3 * page), page, PROT_READ | PROT_EXEC));
        updateProtection(base + 3 * page, page, PROT_READ | PROT_EXEC);
        // Explicit read-only and guard pages must also survive catch-up.
        assert(!mprotect((void*)(base + 4 * page), page, PROT_READ));
        updateProtection(base + 4 * page, page, PROT_READ);
        assert(!mprotect((void*)(base + 5 * page), page, PROT_NONE));
        updateProtection(base + 5 * page, page, PROT_NONE);
        catchup_brk_protection();
        if (getProtection(base + 3 * page) != (PROT_READ | PROT_EXEC) ||
            getProtection(base + 4 * page) != PROT_READ ||
            getProtection(base + 5 * page) != PROT_NONE) {
            fprintf(stderr, "FAIL: %s brk catch-up overwrites explicit page permissions\n",
                    first ? "initial" : "incremental");
            ++failures;
        }
        assert(getProtection(base + 2 * page) == (PROT_READ | PROT_WRITE));
        assert(old_brk == current);
        assert(getMAllocated(base + 5 * page));
        current = base + 7 * page;
        catchup_brk_protection();
        assert(getProtection(base + 6 * page) == (PROT_READ | PROT_WRITE));
    }
    // A later shrink/regrowth still resets newly allocated pages to defaults.
    current = base + 6 * page;
    reset_tracking(base, base + 6 * page);
    setProtection(base, 6 * page, PROT_READ | PROT_WRITE);
    updateProtection(base + 3 * page, page, PROT_READ | PROT_EXEC);
    current = base + page + 13;
    catchup_brk_protection();
    assert(getProtection(base + page) == (PROT_READ | PROT_WRITE));
    current = base + 6 * page;
    catchup_brk_protection();
    assert(getProtection(base + 3 * page) == (PROT_READ | PROT_WRITE));
    rbtree_delete(memprot);
    rbtree_delete(mapallmem);
    assert(!munmap(mapping, 8 * page));
    if (!failures) puts("PASS: brk catch-up preserves explicit permissions; regrowth resets released pages");
    return failures ? 1 : 0;
}
