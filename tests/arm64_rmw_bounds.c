// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "hostext.h"
#include "dynarec/arm64/arm64_lock.h"

cpu_ext_t cpuext;

static uint64_t reference(unsigned op, uint64_t old, uint64_t value, uint64_t extra, uint64_t mask)
{
    old &= mask;
    value &= mask;
    switch (op) {
        case ARM64_RMW_ADD: return (old + value) & mask;
        case ARM64_RMW_OR: return old | value;
        case ARM64_RMW_ADC: return (old + value + extra) & mask;
        case ARM64_RMW_AND: return old & value;
        case ARM64_RMW_XCHG: return value;
        case ARM64_RMW_CMPXCHG: return old == (extra & mask) ? value : old;
        case ARM64_RMW_SUB: return (old - value) & mask;
        case ARM64_RMW_XOR: return old ^ value;
    }
    abort();
}

static void check_bounds(void)
{
    size_t page = sysconf(_SC_PAGESIZE);
    uint8_t* mapping = mmap(NULL, 3 * page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(mapping != MAP_FAILED);
    uint8_t* data = mapping + page;
    assert(!mprotect(data, page, PROT_READ | PROT_WRITE));
    uint8_t* expected = malloc(page);
    assert(expected);
    uint64_t values[] = {0, 1, 0xff, 0xffff, UINT64_C(0x7fffffffffffffff), UINT64_MAX};
    for (unsigned end = 0; end < 2; ++end) {
        size_t base = end ? page - 16 : 0;
        for (unsigned size = 2; size <= 8; size *= 2) {
            uint64_t mask = UINT64_MAX >> (64 - size * 8);
            for (unsigned offset = 0; offset + size <= 16; ++offset) {
                for (unsigned op = ARM64_RMW_ADD; op <= ARM64_RMW_XOR; ++op) {
                    for (unsigned v = 0; v < sizeof(values) / sizeof(values[0]); ++v) {
                        for (unsigned variant = 0; variant < 2; ++variant) {
                            memset(data, 0xa5, page);
                            memcpy(data + base + offset, &values[v], size);
                            memcpy(expected, data, page);
                            uint64_t value = values[(v + 1) % (sizeof(values) / sizeof(values[0]))];
                            uint64_t extra = op == ARM64_RMW_CMPXCHG ? values[v] ^ variant : variant;
                            uint64_t new = reference(op, values[v], value, extra, mask);
                            memcpy(expected + base + offset, &new, size);
                            uint64_t old = arm64_lock_rmw_unaligned(NULL, data + base + offset, value, size, op, extra);
                            assert(old == (values[v] & mask));
                            assert(!memcmp(data, expected, page));
                        }
                    }
                }
            }
        }
    }
    free(expected);
    assert(!munmap(mapping, 3 * page));
}

static _Alignas(16) uint8_t shared[16];
static pthread_barrier_t barrier;
enum { ITERATIONS = 100000 };

static void* mixed_worker(void* argument)
{
    uintptr_t index = (uintptr_t)argument;
    pthread_barrier_wait(&barrier);
    for (unsigned i = 0; i < ITERATIONS; ++i) {
        if (index == 0) {
            arm64_lock_rmw_unaligned(NULL, shared + 1, 1, 8, ARM64_RMW_ADD, 0);
        } else if (index == 1) {
            uint64_t expected = 0, old;
            do {
                old = arm64_lock_rmw_unaligned(NULL, shared + 1, expected + 1, 8,
                                               ARM64_RMW_CMPXCHG, expected);
                if (old == expected) break;
                expected = old;
            } while (1);
        } else if (index == 2) {
            __atomic_fetch_add(shared, 1, __ATOMIC_SEQ_CST);
        } else {
            __atomic_fetch_add((uint32_t*)(shared + 12), 1, __ATOMIC_SEQ_CST);
        }
    }
    return NULL;
}

static void check_mixed(void)
{
    pthread_t threads[4];
    assert(!pthread_barrier_init(&barrier, NULL, 4));
    for (uintptr_t i = 0; i < 4; ++i)
        assert(!pthread_create(&threads[i], NULL, mixed_worker, (void*)i));
    for (unsigned i = 0; i < 4; ++i)
        assert(!pthread_join(threads[i], NULL));
    assert(!pthread_barrier_destroy(&barrier));
    uint8_t expected[16] = {0};
    uint64_t counter = 2 * ITERATIONS;
    uint32_t neighbor = ITERATIONS;
    expected[0] = (uint8_t)ITERATIONS;
    memcpy(expected + 1, &counter, sizeof(counter));
    memcpy(expected + 12, &neighbor, sizeof(neighbor));
    assert(!memcmp(expected, shared, sizeof(shared)));
}

typedef struct {
    unsigned offset, size, native_offset;
} overlap_case_t;

static overlap_case_t overlap;
static uint64_t ticket_sums[4];

static void* overlap_worker(void* argument)
{
    uintptr_t index = (uintptr_t)argument;
    unsigned first = overlap.offset > overlap.native_offset ? overlap.offset : overlap.native_offset;
    unsigned bits = 8 * (overlap.offset + overlap.size - first);
    unsigned helper_shift = 8 * (first - overlap.offset);
    unsigned native_shift = 8 * (first - overlap.native_offset);
    uint64_t counter_mask = UINT64_MAX >> (64 - bits);
    uint64_t helper_mask = UINT64_MAX >> (64 - 8 * overlap.size);
    uint64_t native_mask = counter_mask << native_shift;
    uint64_t increment = UINT64_C(1) << helper_shift;
    uint64_t* native = (uint64_t*)(shared + overlap.native_offset);
    uint64_t sum = 0;
    pthread_barrier_wait(&barrier);
    for (unsigned i = 0; i < ITERATIONS; ++i) {
        uint64_t old;
        if (index == 0 || index == 2) {
            old = index == 0
                ? arm64_lock_xadd_unaligned(NULL, shared + overlap.offset, increment, overlap.size)
                : arm64_lock_rmw_unaligned(NULL, shared + overlap.offset, increment,
                                           overlap.size, ARM64_RMW_ADD, 0);
            sum += (old >> helper_shift) & counter_mask;
        } else if (index == 1) {
            uint64_t expected = 0;
            do {
                old = arm64_lock_rmw_unaligned(NULL, shared + overlap.offset,
                                               (expected + increment) & helper_mask,
                                               overlap.size, ARM64_RMW_CMPXCHG, expected);
                if (old == expected) break;
                expected = old;
            } while (1);
            sum += (old >> helper_shift) & counter_mask;
        } else {
            old = __atomic_load_n(native, __ATOMIC_RELAXED);
            uint64_t replacement;
            do {
                uint64_t count = ((old >> native_shift) + 1) & counter_mask;
                replacement = (old & ~native_mask) | (count << native_shift);
            } while (!__atomic_compare_exchange_n(native, &old, replacement, 1,
                                                  __ATOMIC_SEQ_CST, __ATOMIC_RELAXED));
            sum += (old >> native_shift) & counter_mask;
        }
    }
    ticket_sums[index] = sum;
    return NULL;
}

static void check_overlapping(void)
{
    // Native aligned CAS updates the same bits as each unaligned helper.
    // The second half cases force the helper to reserve a complete 16-byte pair.
    const overlap_case_t cases[] = {
        {1, 2, 0}, {1, 4, 0}, {9, 4, 8}, {8, 8, 8},
        {7, 2, 8}, {6, 4, 8}, {1, 8, 8}, {3, 8, 8}, {7, 8, 8},
    };
    for (unsigned c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c) {
        overlap = cases[c];
        unsigned first = overlap.offset > overlap.native_offset ? overlap.offset : overlap.native_offset;
        unsigned bytes = overlap.offset + overlap.size - first;
        uint64_t mask = UINT64_MAX >> (64 - 8 * bytes);
        uint8_t expected[16];
        for (unsigned i = 0; i < sizeof(shared); ++i) shared[i] = 0xa5 ^ (i * 37);
        memset(shared + first, 0, bytes);
        memcpy(expected, shared, sizeof(expected));
        pthread_t threads[4];
        assert(!pthread_barrier_init(&barrier, NULL, 4));
        for (uintptr_t i = 0; i < 4; ++i)
            assert(!pthread_create(&threads[i], NULL, overlap_worker, (void*)i));
        for (unsigned i = 0; i < 4; ++i)
            assert(!pthread_join(threads[i], NULL));
        assert(!pthread_barrier_destroy(&barrier));
        uint64_t total = 4 * ITERATIONS, count = total & mask;
        memcpy(expected + first, &count, bytes);
        assert(!memcmp(expected, shared, sizeof(shared)));

        // The return values must be a permutation of the serial ticket sequence,
        // including wrapping byte/word counters. A final count alone is weaker.
        uint64_t expected_sum;
        if (mask >= total) {
            expected_sum = total * (total - 1) / 2;
        } else {
            uint64_t period = mask + 1, remainder = total % period;
            expected_sum = (total / period) * period * (period - 1) / 2
                           + remainder * (remainder - 1) / 2;
        }
        uint64_t actual_sum = 0;
        for (unsigned i = 0; i < 4; ++i) actual_sum += ticket_sums[i];
        assert(actual_sum == expected_sum);
    }
}

static unsigned lock_offset;
static uint64_t protected_counter;

static void* lock_worker(void* ignored)
{
    pthread_barrier_wait(&barrier);
    for (unsigned i = 0; i < ITERATIONS; ++i) {
        while (arm64_lock_rmw_unaligned(NULL, shared + lock_offset, 1, 4, ARM64_RMW_XCHG, 0)) {}
        ++protected_counter;
        arm64_lock_rmw_unaligned(NULL, shared + lock_offset, 0, 4, ARM64_RMW_XCHG, 0);
    }
    return NULL;
}

static void check_locks(void)
{
    for (lock_offset = 0; lock_offset <= 12; ++lock_offset) {
        pthread_t threads[2];
        memset(shared, 0, sizeof(shared));
        protected_counter = 0;
        assert(!pthread_barrier_init(&barrier, NULL, 2));
        for (unsigned i = 0; i < 2; ++i)
            assert(!pthread_create(&threads[i], NULL, lock_worker, NULL));
        for (unsigned i = 0; i < 2; ++i)
            assert(!pthread_join(threads[i], NULL));
        assert(!pthread_barrier_destroy(&barrier));
        assert(protected_counter == 2 * ITERATIONS);
        for (unsigned i = 0; i < sizeof(shared); ++i) assert(!shared[i]);
    }
}

int main(void)
{
    alarm(20);
    check_bounds();
    check_mixed();
    check_overlapping();
    check_locks();
    puts("PASS: all RMW operations, carry/compare variants, guard pages, neighboring/overlapping native atomics, tickets and unaligned spinlocks");
    return 0;
}
