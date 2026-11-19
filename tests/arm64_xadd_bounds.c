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
    for (unsigned end = 0; end != 2; ++end) {
        size_t base = end ? page - 16 : 0;
        for (unsigned size = 2; size <= 8; size *= 2) {
            uint64_t mask = UINT64_MAX >> (64 - size * 8);
            for (unsigned offset = 0; offset + size <= 16; ++offset) {
                for (unsigned v = 0; v < sizeof(values) / sizeof(values[0]); ++v) {
                    memset(data, 0xa5, page);
                    memcpy(data + base + offset, &values[v], size);
                    memcpy(expected, data, page);
                    uint64_t addend = values[(v + 1) % (sizeof(values) / sizeof(values[0]))];
                    uint64_t new = (values[v] + addend) & mask;
                    memcpy(expected + base + offset, &new, size);
                    uint64_t old = arm64_lock_xadd_unaligned(NULL, data + base + offset, addend, size);
                    assert(old == (values[v] & mask));
                    assert(!memcmp(data, expected, page));
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

static void* worker(void* argument)
{
    uintptr_t index = (uintptr_t)argument;
    pthread_barrier_wait(&barrier);
    for (unsigned i = 0; i != ITERATIONS; ++i) {
        if (index < 2)
            arm64_lock_xadd_unaligned(NULL, shared + 1, 1, 8);
        else if (index == 2)
            __atomic_fetch_add(shared, 1, __ATOMIC_SEQ_CST);
        else
            __atomic_fetch_add((uint32_t*)(shared + 12), 1, __ATOMIC_SEQ_CST);
    }
    return NULL;
}

static void check_neighbors(void)
{
    pthread_t threads[4];
    assert(!pthread_barrier_init(&barrier, NULL, 4));
    for (uintptr_t i = 0; i != 4; ++i)
        assert(!pthread_create(&threads[i], NULL, worker, (void*)i));
    for (unsigned i = 0; i != 4; ++i)
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

int main(void)
{
    check_bounds();
    check_neighbors();
    puts("PASS: XADD return values, overflow, guard pages and concurrent neighboring atomics");
    return 0;
}
