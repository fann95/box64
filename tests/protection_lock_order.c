// SPDX-License-Identifier: MIT
// The runner inserts current production functions; only their external services
// are replaced here so the two-thread lock schedule is deterministic.
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>

#define DYNAREC 1
#define dynarec_log(...) ((void)0)
#define printf_log(...) ((void)0)
#define BOX64ENV(x) dynarec_enabled
#define ALIGN(x) (((x) + 4095) & ~4095UL)
#define ALIGN_DOWN(x) ((x) & ~4095UL)
#include "protection_flags.inc"

typedef struct {
    int gone, done;
    void *block, *actual_block, *x64_addr;
    size_t x64_size, size;
} dynablock_t;
static struct {
    pthread_mutex_t mutex_dyndump;
    uintptr_t max_db_size;
    void* db_sizes;
} context;
static typeof(context)* my_context = &context;
static pthread_mutex_t mutex_prot;
static sem_t jit_holds, removal_waiting;
static _Thread_local int role, announced, holds_prot, holds_dyndump, critical_depth;
static int setting_prot;
static int dynarec_enabled = 1, freed, marked;
static uint32_t old_prot, stored_prot;
static void* memprot;
static dynablock_t block;

static int tracked_lock(pthread_mutex_t* mutex)
{
    if (role == 2 && !announced && mutex == &context.mutex_dyndump) {
        announced = 1;
        sem_post(&removal_waiting);
    }
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 2;
    int error = pthread_mutex_timedlock(mutex, &deadline);
    if (error == EDEADLK)
        return error; // The production scoped guard must preserve the outer owner.
    if (error) {
        fprintf(stderr, "FAIL: role %d lock error %d (prot=%d, dyndump=%d)\n",
                role, error, holds_prot, holds_dyndump);
        exit(1);
    }
    if (mutex == &mutex_prot) holds_prot = 1;
    else holds_dyndump = 1;
    if (role == 2 && !announced) {
        announced = 1;
        sem_post(&removal_waiting);
    }
    return 0;
}
static void tracked_unlock(pthread_mutex_t* mutex)
{
    if (mutex == &mutex_prot) { assert(holds_prot); holds_prot = 0; }
    else { assert(holds_dyndump); holds_dyndump = 0; }
    assert(!pthread_mutex_unlock(mutex));
}
#define mutex_lock(p) tracked_lock(p)
#define mutex_unlock(p) tracked_unlock(p)
static void enter_critical_section(void) { ++critical_depth; }
static void leave_critical_section(void) { assert(critical_depth > 0); --critical_depth; }
#define LOCK_PROT() do { enter_critical_section(); assert(!mutex_lock(&mutex_prot)); } while (0)
#define UNLOCK_PROT() do { mutex_unlock(&mutex_prot); leave_critical_section(); } while (0)
static int IsDynablockLive(dynablock_t* d) { assert(holds_prot); return d == &block; }
static dynablock_t* getDB(uintptr_t a) { return a == (uintptr_t)block.x64_addr ? &block : NULL; }
static void FreeDynablockGdbJIT(dynablock_t* d) {}
static void setJumpTableDefault64(void* a) {}
static uint32_t rb_dec(void* t, uintptr_t a, uintptr_t b) { return 1; }
static uintptr_t rb_get_rightmost(void* t) { return 16; }
static void DeferFreeDynablockMap(dynablock_t* d) { assert(holds_dyndump); ++freed; }
static uintptr_t getDBSize(uintptr_t a, size_t s, dynablock_t** d) { *d = &block; return a + s; }
static void MarkRangeDynablock(dynablock_t* d, uintptr_t a, size_t s) { ++marked; }
static void MarkCRCRangeDynablock(dynablock_t* d, uintptr_t a, size_t s) { ++marked; }
static void setGuestDynProtection_locked(uintptr_t a, size_t s) { assert(holds_prot); }
static void rb_get_end(void* t, uintptr_t a, uint32_t* p, uintptr_t* e)
{ assert(holds_prot); *p = old_prot; *e = a + 4096; }
static int applyDBHostPageProtection_locked(uintptr_t a, uintptr_t b, uint32_t p, uintptr_t c, uintptr_t d, int e) { return 0; }
static void catchup_brk_protection(void) { assert(!holds_prot && !holds_dyndump); }
static int imposeWriteProtection_locked(uintptr_t a, uintptr_t b, uint32_t p) { return 1; }
static void flagUnprotectedNeighbours_locked(uintptr_t a) {}
static void rb_set(void* t, uintptr_t a, uintptr_t b, uint32_t p)
{ assert(holds_prot); stored_prot = p; }
#include "protection_functions.inc"

static void reset(uint32_t prot)
{
    old_prot = stored_prot = prot;
    freed = marked = 0;
    block = (dynablock_t){.done = 1, .x64_addr = (void*)0x400000, .x64_size = 16};
    context.max_db_size = 16;
}
static void* jit(void* ignored)
{
    role = 1;
    mutex_lock(&context.mutex_dyndump);
    sem_post(&jit_holds);
    sem_wait(&removal_waiting);
    protectDB(0x500000, 1);
    assert(!holds_prot && holds_dyndump && !critical_depth);
    mutex_unlock(&context.mutex_dyndump);
    return NULL;
}
static void* remover(void* ignored)
{
    role = 2;
    sem_wait(&jit_holds);
    updateProtection(0x400000, 4096, PROT_NONE);
    assert(!holds_prot && !holds_dyndump && !critical_depth);
    return NULL;
}
int main(void)
{
    pthread_mutexattr_t attr;
    assert(!pthread_mutexattr_init(&attr));
    assert(!pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK));
    assert(!pthread_mutex_init(&mutex_prot, &attr));
    assert(!pthread_mutex_init(&context.mutex_dyndump, &attr));
    assert(!pthread_mutexattr_destroy(&attr));
    sem_init(&jit_holds, 0, 0);
    sem_init(&removal_waiting, 0, 0);
    reset(PROT_READ | PROT_EXEC);
    pthread_t a, b;
    assert(!pthread_create(&a, NULL, jit, NULL));
    assert(!pthread_create(&b, NULL, remover, NULL));
    assert(!pthread_join(a, NULL));
    assert(!pthread_join(b, NULL));
    assert(freed == 1 && block.gone && stored_prot == PROT_NONE);
    reset(PROT_READ | PROT_EXEC | PROT_NEVERCLEAN);
    updateProtection(0x400000, 4096, PROT_NONE);
    assert(!freed && stored_prot == PROT_NEVERCLEAN);
    reset(PROT_READ | PROT_EXEC | PROT_NOPROT);
    updateProtection(0x400000, 4096, PROT_NONE);
    assert(!freed && stored_prot == old_prot);
    reset(PROT_READ | PROT_EXEC);
    updateProtection(0x400000, 4096, PROT_READ);
    assert(!freed && marked == 1 && stored_prot == PROT_READ);
    reset(PROT_READ | PROT_EXEC);
    block.x64_addr -= 16;
    block.x64_size = 8;
    updateProtection(0x400000, 4096, PROT_NONE);
    assert(!freed && stored_prot == PROT_NONE);
    reset(PROT_READ | PROT_EXEC);
    dynarec_enabled = 0;
    updateProtection(0x400000, 4096, PROT_NONE);
    assert(!freed && stored_prot == PROT_NONE);
    assert(!holds_prot && !holds_dyndump);
#ifdef HAVE_DYNABLOCK_MEMORY_GUARD
    LOCK_PROT();
    int token = LockDynablockMemory();
    assert(!token && setting_prot == 1 && critical_depth == 2);
    UnlockDynablockMemory(token);
    assert(holds_prot && !setting_prot && critical_depth == 1);
    assert(pthread_mutex_trylock(&mutex_prot) == EBUSY);
    UNLOCK_PROT();
    token = LockDynablockMemory();
    assert(token && holds_prot && setting_prot == 1);
    UnlockDynablockMemory(token);
    assert(!holds_prot && !setting_prot && !critical_depth);
    dynarec_enabled = 1;
    reset(PROT_READ | PROT_EXEC);
    assert(cleanDBFromAddressRange(0x400000, 4096, 1));
    assert(freed == 1 && block.gone == 2);
    FreeDynablock(&block, 1, 1);
    assert(freed == 1); // The same allocation must not enter the queue twice.
    FreeDynablock((dynablock_t*)1, 1, 1);
    assert(FreeRangeDynablock((dynablock_t*)1, 0x400000, 4096) == 1);
    assert(!holds_prot && !holds_dyndump && !setting_prot && !critical_depth);
#endif
    puts("PASS: JIT/protection lock ordering, scoped guard ownership, exact destruction and excluded-page semantics");
    return 0;
}
