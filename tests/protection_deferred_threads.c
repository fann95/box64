// SPDX-License-Identifier: MIT
// Exercise production allocator/guard functions with a scheduled foreign allocation.
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#define printf_log(...) ((void)0)
#define ALIGN(x) (((x) + 4095) & ~4095UL)
#define ALIGN_DOWN(x) ((x) & ~4095UL)
#define BTYPE_MAP64 2
#define MMAPSIZE64 (64 * 2048)
#ifndef MAP_32BIT
#define MAP_32BIT 0
#endif
typedef enum { MEM_ALLOCATED = 1 } mem_flag_t;
typedef struct {
    void *block;
    size_t maxfree, size;
    void *first;
    uint32_t lowest;
    uint8_t type, is32bits;
} blocklist_t;
static blocklist_t *p_blocks;
static int n_blocks, c_blocks, box64_is32bits;
static int last_block_index = -1, last_block_index_map64 = -1;
static pthread_mutex_t mutex_prot, mutex_blocks;
static sem_t foreign_routed;
static _Thread_local int foreign_thread, announced, critical_depth;
static int map_tree, prot_tree;
static void *mapallmem = &map_tree, *memprot = &prot_tree;
static uintptr_t registered[8];
static int n_registered;
static void *foreign_allocation;

static int tracked_lock(pthread_mutex_t *mutex)
{
    if (foreign_thread && !announced && mutex == &mutex_prot) {
        announced = 1;
        assert(!sem_post(&foreign_routed));
    }
    return pthread_mutex_lock(mutex);
}
#define mutex_lock(p) tracked_lock(p)
#define mutex_unlock(p) pthread_mutex_unlock(p)
static void enter_critical_section(void) { ++critical_depth; }
static void leave_critical_section(void) { assert(critical_depth > 0); --critical_depth; }
static void rb_set(void *tree, uintptr_t start, uintptr_t end, uint32_t value)
{
    (void)end; (void)value;
    if (tree == mapallmem) {
        assert(n_registered < 8);
        registered[n_registered++] = start;
    }
}
static void rb_unset(void *tree, uintptr_t start, uintptr_t end) {}
static void add_blockstree(uintptr_t start, uintptr_t end, int index) {}
#define box_realloc realloc
#define InternalMmap mmap
#define box_mmap mmap
static void *box32_dynarec_mmap(size_t size, int fd, off_t offset)
{ abort(); }
static void setProtection_generic(uintptr_t, size_t, uint32_t, mem_flag_t);
static void setProtection(uintptr_t, size_t, uint32_t);
#include "deferred_protection_production.inc"

static void *allocate_foreign(void *unused)
{
    foreign_thread = 1;
    foreign_allocation = map64_customMalloc(64, 0);
    if (!announced) {
        announced = 1;
        assert(!sem_post(&foreign_routed));
    }
    assert(!critical_depth);
    return NULL;
}
int main(void)
{
    pthread_mutexattr_t attr;
    assert(!pthread_mutexattr_init(&attr));
    assert(!pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK));
    assert(!pthread_mutex_init(&mutex_prot, &attr));
    assert(!pthread_mutex_init(&mutex_blocks, &attr));
    assert(!pthread_mutexattr_destroy(&attr));
    assert(!sem_init(&foreign_routed, 0, 0));
    int token = LockDynablockMemory();
    void *own_allocation = map64_customMalloc(64, 0);
    // Fill the first production bitmap pool; the foreign allocation needs a new one.
    while (p_blocks[0].maxfree)
        assert(map64_customMalloc(64, 0));
    assert(n_blocks == 1 && !n_registered);
    pthread_t other;
    assert(!pthread_create(&other, NULL, allocate_foreign, NULL));
    assert(!sem_wait(&foreign_routed));
    UnlockDynablockMemory(token);
    assert(!pthread_join(other, NULL));
    int own_seen = 0, foreign_seen = 0;
    for (int i = 0; i < n_registered; ++i) {
        own_seen |= registered[i] == (uintptr_t)own_allocation;
        foreign_seen |= registered[i] == (uintptr_t)foreign_allocation;
    }
    if (!own_seen || !foreign_seen) {
        fprintf(stderr, "FAIL: owner mapping registered=%d, foreign mapping registered=%d; shared deferral lost a mapping\n",
                own_seen, foreign_seen);
        return 1;
    }
    assert(!critical_depth && !setting_prot && !defered_prot_p);
    for (int i = 0; i < n_blocks; ++i)
        assert(!munmap(p_blocks[i].block, p_blocks[i].size));
    free(p_blocks);
    puts("PASS: concurrent custom allocation preserves both protection registrations");
    return 0;
}
