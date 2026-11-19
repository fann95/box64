// SPDX-License-Identifier: MIT
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define WIDTH 4
#define JMPTABL_START0 0
#define JMPTABL_START1 2
#define JMPTABL_START2 4
#define JMPTABL_START3 6
#define JMPTABLE_MASK0 3
#define JMPTABLE_MASK1 3
#define JMPTABLE_MASK2 3
#define JMPTABLE_MASK3 3
static char next_code, old_code, new_code, unrelated_code;
static void* native_next = &next_code;
static uintptr_t box64_jmptbldefault0[WIDTH];
static uintptr_t* box64_jmptbldefault1[WIDTH];
#ifdef TEST_FOUR_LEVELS
#define JMPTABL_SHIFT4 2
static uintptr_t** box64_jmptbldefault2[WIDTH];
static uintptr_t*** box64_jmptbl3[WIDTH];
#else
static uintptr_t** box64_jmptbl2[WIDTH];
#endif
static void* allocations[32];
static int allocated, create_calls;
static void* allocate_table(void* initial)
{
    uintptr_t* table = calloc(WIDTH, sizeof(*table));
    assert(table && allocated < 32);
    allocations[allocated++] = table;
    for(int i=0; i<WIDTH; ++i) table[i] = (uintptr_t)initial;
    return table;
}
static void reset(void)
{
    while(allocated) free(allocations[--allocated]);
    for(int i=0; i<WIDTH; ++i) {
        box64_jmptbldefault0[i] = (uintptr_t)native_next;
        box64_jmptbldefault1[i] = box64_jmptbldefault0;
#ifdef TEST_FOUR_LEVELS
        box64_jmptbldefault2[i] = box64_jmptbldefault1;
        box64_jmptbl3[i] = box64_jmptbldefault2;
#else
        box64_jmptbl2[i] = box64_jmptbldefault1;
#endif
    }
    create_calls = 0;
}
static uintptr_t* create_jmptbl(int for32bits, uintptr_t i0, uintptr_t i1, uintptr_t i2
#ifdef TEST_FOUR_LEVELS
    , uintptr_t i3
#endif
)
{
    ++create_calls;
#ifdef TEST_FOUR_LEVELS
    if(box64_jmptbl3[i3] == box64_jmptbldefault2)
        box64_jmptbl3[i3] = allocate_table(box64_jmptbldefault1);
    uintptr_t*** table2 = box64_jmptbl3[i3];
#else
    uintptr_t*** table2 = box64_jmptbl2;
#endif
    if(table2[i2] == box64_jmptbldefault1)
        table2[i2] = allocate_table(box64_jmptbldefault0);
    if(table2[i2][i1] == box64_jmptbldefault0)
        table2[i2][i1] = allocate_table(native_next);
    return &table2[i2][i1][i0];
}
static void* native_lock_storeifref2(uintptr_t* entry, void* replacement, void* expected)
{
    uintptr_t old = (uintptr_t)expected;
    __atomic_compare_exchange_n(entry, &old, (uintptr_t)replacement, 0,
        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return (void*)old;
}
#include "jumptable_function.inc"

int main(void)
{
    void* addr = (void*)(1 | (2<<2) | (3<<4) | (1<<6));
#ifdef TEST_FOUR_LEVELS
    const int levels = 3;
#else
    const int levels = 2;
#endif
    for(int missing=0; missing<levels; ++missing) {
        reset();
#ifdef TEST_FOUR_LEVELS
        if(missing) box64_jmptbl3[1] = allocate_table(box64_jmptbldefault1);
        if(missing>1) box64_jmptbl3[1][3] = allocate_table(box64_jmptbldefault0);
#else
        if(missing) box64_jmptbl2[3] = allocate_table(box64_jmptbldefault0);
#endif
        int before = allocated;
        assert(!setJumpTableIfRef64(addr, &new_code, &old_code));
        assert(allocated == before && create_calls == 0);
        assert(setJumpTableIfRef64(addr, native_next, &old_code));
        assert(allocated == before && create_calls == 0);
        // The default reference still permits creating missing levels.
        assert(setJumpTableIfRef64(addr, &old_code, native_next));
        assert(allocated > before && create_calls == 1);
        assert(setJumpTableIfRef64(addr, &new_code, &old_code));
        // Already equal to replacement: report success despite ref mismatch.
        assert(setJumpTableIfRef64(addr, &new_code, &unrelated_code));
        assert(!setJumpTableIfRef64(addr, &old_code, &unrelated_code));
        assert(setJumpTableIfRef64(addr, native_next, &new_code));
        assert(setJumpTableIfRef64(addr, native_next, &old_code));
    }
    reset();
    assert(!setJumpTableIfRef64((void*)UINT64_C(0xffff000000000000), &new_code, &old_code));
    assert(!allocated && !create_calls);
    puts("PASS: missing references avoid allocation; CAS/default/no-op semantics preserved");
    return 0;
}
