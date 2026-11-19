// SPDX-License-Identifier: MIT
#include <assert.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include "tools/cleanup.c"

enum { THREADS = 8, PER_THREAD = 2048, TOTAL = THREADS * PER_THREAD };
box64context_t* my_context;
box64env_t box64env;
static elfheader_t header;
static pthread_barrier_t start;
static int kind, seen[TOTAL + 1], nested, sequence[3], sequence_size;
static atomic_int calls;

void PrintfFtrace(int prefix, const char* format, ...) {}
void enter_critical_section(void) {}
void leave_critical_section(void) {}

uint64_t RunFunctionWithEmu(x64emu_t* emu, int quit, uintptr_t fnc, int nargs, ...)
{
    if (nested) {
        assert(sequence_size < 3);
        sequence[sequence_size++] = fnc;
        if (fnc == 2) {
            if (kind == 0) AddCleanup(NULL, (void*)3);
            else if (kind == 1) AddCleanup1Arg(NULL, (void*)3, NULL, &header);
            else AddQuickCleanup(NULL, (void*)3);
        }
    } else {
        assert(fnc > 0 && fnc <= TOTAL);
        assert(__atomic_fetch_add(&seen[fnc], 1, __ATOMIC_RELAXED) == 0);
        atomic_fetch_add(&calls, 1);
    }
    return 0;
}

static void add(uintptr_t id)
{
    if (kind == 0) AddCleanup(NULL, (void*)id);
    else if (kind == 1) AddCleanup1Arg(NULL, (void*)id, (void*)id, &header);
    else AddQuickCleanup(NULL, (void*)id);
}

static void finish(void)
{
    if (kind == 0) CallAllCleanup(NULL);
    else if (kind == 1) CallCleanup(NULL, &header);
    else CallQuickCleanup(NULL, 0);
}

static void* register_thread(void* arg)
{
    uintptr_t offset = (uintptr_t)arg * PER_THREAD;
    pthread_barrier_wait(&start);
    for (int i = 1; i <= PER_THREAD; ++i) add(offset + i);
    return NULL;
}

static void reset(void)
{
    free(my_context->cleanups);
    free(my_context->quick_cleanups);
    free(header.cleanups);
    my_context->cleanups = my_context->quick_cleanups = header.cleanups = NULL;
    my_context->clean_sz = my_context->clean_cap = 0;
    my_context->quick_clean_sz = my_context->quick_clean_cap = 0;
    header.clean_sz = header.clean_cap = 0;
    memset(seen, 0, sizeof(seen));
    calls = 0;
}

static int concurrent(int preallocate)
{
    reset();
    if (preallocate) {
        cleanup_t* array = calloc(TOTAL, sizeof(cleanup_t));
        assert(array);
        if (kind == 0) { my_context->cleanups = array; my_context->clean_cap = TOTAL; }
        else if (kind == 1) { header.cleanups = array; header.clean_cap = TOTAL; }
        else { my_context->quick_cleanups = array; my_context->quick_clean_cap = TOTAL; }
    }
    pthread_t threads[THREADS];
    for (uintptr_t i = 0; i < THREADS; ++i)
        assert(pthread_create(&threads[i], NULL, register_thread, (void*)i) == 0);
    for (int i = 0; i < THREADS; ++i) assert(pthread_join(threads[i], NULL) == 0);
    int size = kind == 0 ? my_context->clean_sz : kind == 1 ? header.clean_sz : my_context->quick_clean_sz;
    if (size != TOTAL) {
        fprintf(stderr, "FAIL: cleanup kind %d retained %d of %d registrations\n", kind, size, TOTAL);
        return 1;
    }
    finish();
    assert(calls == TOTAL);
    for (int i = 1; i <= TOTAL; ++i) assert(seen[i] == 1);
    return 0;
}

int main(void)
{
    box64context_t context = {0};
    my_context = &context;
    assert(pthread_mutex_init(&context.mutex_cleanup, NULL) == 0);
    assert(pthread_barrier_init(&start, NULL, THREADS) == 0);
    int failures = 0;
    for (kind = 0; kind < 3; ++kind) failures += concurrent(1);
    // Do not risk a corrupting concurrent realloc after the basic race failed.
    if (!failures) for (kind = 0; kind < 3; ++kind) failures += concurrent(0);
    nested = 1;
    for (kind = 0; kind < 3; ++kind) {
        reset();
        sequence_size = 0;
        add(1); add(2);
        finish();
        if (sequence_size != 3 || sequence[0] != 2 || sequence[1] != 3 || sequence[2] != 1) {
            fprintf(stderr, "FAIL: cleanup kind %d lost or reordered a nested registration\n", kind);
            ++failures;
        }
    }
    reset();
    pthread_barrier_destroy(&start);
    pthread_mutex_destroy(&context.mutex_cleanup);
    if (!failures) puts("PASS: all cleanup lists preserve concurrent and nested registrations");
    return failures ? 1 : 0;
}
