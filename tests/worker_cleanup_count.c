// SPDX-License-Identifier: MIT
// Exercise production worker/cancellation/destructor paths with real pthread TLS.
#include <assert.h>
#include <pthread.h>
#include <semaphore.h>
#include <setjmp.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct x64emu_s {
    struct { int quitonlongjmp; } flags;
    int quit, type;
    uintptr_t rax, rsp, rbp, rip, rdi;
} x64emu_t;
typedef unsigned long ulong_t;
typedef struct { jmp_buf __cancel_jmp_buf; } x64_unwind_buff_t;
#include "worker_type.inc"

static pthread_key_t thread_key;
static _Atomic int g_active_emu_workers;
static sem_t cleanup_entered, cleanup_continue, guest_running, guest_wait;
static int mode;
static atomic_int errors, cleanup_calls, free_calls;
static int expected_active;

#define EMUTYPE_MAIN 0
#define printf_log(...) ((void)0)
#define box_free free
#define box_calloc calloc
#define R_RAX emu->rax
#define R_RSP emu->rsp
#define R_RBP emu->rbp
#define R_RIP emu->rip
#define R_RDI emu->rdi

static void expect_count(const char *where)
{
    int actual = atomic_load(&g_active_emu_workers);
    if (actual != expected_active) {
        fprintf(stderr, "FAIL: %s saw %d active workers, expected %d\n",
                where, actual, expected_active);
        atomic_fetch_add(&errors, 1);
    }
}

static void CallThreadCleanup(x64emu_t *emu)
{
    (void)emu;
    expect_count("TLS destructor");
    atomic_fetch_add(&cleanup_calls, 1);
    assert(!sem_post(&cleanup_entered));
    assert(!sem_wait(&cleanup_continue));
    expect_count("TLS destructor completion");
}

static void FreeX64Emu(x64emu_t **emu)
{
    expect_count("emulator release");
    atomic_fetch_add(&free_calls, 1);
    free(*emu);
    *emu = NULL;
}

static void my_longjmp(x64emu_t *emu, void *buffer, int value) { abort(); }
static void refreshTLSData(x64emu_t *emu) {}
static void Push64(x64emu_t *emu, uint64_t value) {}
static void PushExit(x64emu_t *emu) {}
static void DynaRun(x64emu_t *emu)
{
    emu->rax = 17;
    if (mode == 1) {
        assert(!sem_post(&guest_running));
        for (;;) assert(!sem_wait(&guest_wait));
    }
}

#include "worker_functions.inc"

static emuthread_t *new_thread(void)
{
    emuthread_t *et = calloc(1, sizeof(*et));
    assert(et);
    et->emu = calloc(1, sizeof(*et->emu));
    assert(et->emu);
    return et;
}

static void *explicit_clear(void *p)
{
    emuthread_t *et = p;
    assert(!pthread_setspecific(thread_key, et));
    thread_set_emu(NULL);
    thread_set_emu(NULL); // Must not release the worker again.
    assert(!pthread_getspecific(thread_key));
    return NULL;
}

static void exercise(int selected_mode)
{
    mode = selected_mode;
    cleanup_calls = free_calls = 0;
    expected_active = 1;
    emuthread_t *et = new_thread();
    g_active_emu_workers = mode < 2 ? 0 : 1;
    // Explicit destruction can occur before pthread's own key cleanup.
    if (mode == 2) et->counted_worker = 1;
    // Mode 3 models an uncounted main/foreign/32-bit emu while another worker exists.
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, mode < 2 ? pthread_routine : explicit_clear, et));
    if (mode == 1) {
        assert(!sem_wait(&guest_running));
        assert(!pthread_cancel(thread));
    }
    assert(!sem_wait(&cleanup_entered));
    expect_count("shutdown observer while destructor is blocked");
    assert(!sem_post(&cleanup_continue));
    void *result;
    assert(!pthread_join(thread, &result));
    if (mode == 0) assert(result == (void *)17);
    if (mode == 1) assert(result == PTHREAD_CANCELED);
    int remaining = atomic_load(&g_active_emu_workers);
    if (remaining != (mode == 3 ? 1 : 0)) {
        fprintf(stderr, "FAIL: mode %d left active count %d\n", mode, remaining);
        ++errors;
    }
    assert(cleanup_calls == 1 && free_calls == 1);
}

int main(void)
{
    assert(!pthread_key_create(&thread_key, emuthread_destroy));
    assert(!sem_init(&cleanup_entered, 0, 0));
    assert(!sem_init(&cleanup_continue, 0, 0));
    assert(!sem_init(&guest_running, 0, 0));
    assert(!sem_init(&guest_wait, 0, 0));
    for (int i = 0; i < 4; ++i) exercise(i);
    assert(!pthread_key_delete(thread_key));
    assert(!sem_destroy(&cleanup_entered));
    assert(!sem_destroy(&cleanup_continue));
    assert(!sem_destroy(&guest_running));
    assert(!sem_destroy(&guest_wait));
    if (errors) return 1;
    puts("PASS: worker remains active through normal/cancelled TLS cleanup; explicit and uncounted cleanup balance");
    return 0;
}
