// SPDX-License-Identifier: MIT
#include <string.h>
#include <limits.h>

#include "cleanup.h"
#include "elfs/elfloader_private.h"
#include "box64context.h"
#include "debug.h"
#include "callback.h"
#include "emu/x64emu_private.h"
#include "signals.h"
#include "librarian.h"
#include "library.h"

typedef struct cleanup_s {
    void*       f;
    int         arg;
    void*       a;
    elfheader_t* dso;
} cleanup_t;

static void lock_cleanup(void)
{
    enter_critical_section();
    pthread_mutex_lock(&my_context->mutex_cleanup);
}

static void unlock_cleanup(void)
{
    pthread_mutex_unlock(&my_context->mutex_cleanup);
    leave_critical_section();
}

void AddCleanup(x64emu_t *emu, void *p)
{
    (void)emu;

    lock_cleanup();
    if(my_context->clean_sz == my_context->clean_cap) {
        my_context->clean_cap += 32;
        my_context->cleanups = (cleanup_t*)box_realloc(my_context->cleanups, sizeof(cleanup_t)*my_context->clean_cap);
    }
    my_context->cleanups[my_context->clean_sz].arg = 0;
    my_context->cleanups[my_context->clean_sz].a = NULL;
    my_context->cleanups[my_context->clean_sz].dso = NULL;
    my_context->cleanups[my_context->clean_sz++].f = p;
    unlock_cleanup();
}

void AddCleanup1Arg(x64emu_t *emu, void *p, void* a, elfheader_t* h)
{
    (void)emu;
    lock_cleanup();
    if (!h)
        h = my_context->elfs[0];

    if(h->clean_sz == h->clean_cap) {
        h->clean_cap += 32;
        h->cleanups = (cleanup_t*)box_realloc(h->cleanups, sizeof(cleanup_t)*h->clean_cap);
    }
    h->cleanups[h->clean_sz].arg = 1;
    h->cleanups[h->clean_sz].a = a;
    h->cleanups[h->clean_sz].dso = NULL;
    h->cleanups[h->clean_sz++].f = p;
    unlock_cleanup();
}

void AddQuickCleanup(x64emu_t *emu, void *p)
{
    (void)emu;

    lock_cleanup();
    if(my_context->quick_clean_sz == my_context->quick_clean_cap) {
        my_context->quick_clean_cap += 32;
        my_context->quick_cleanups = (cleanup_t*)box_realloc(my_context->quick_cleanups, sizeof(cleanup_t) * my_context->quick_clean_cap);
    }
    my_context->quick_cleanups[my_context->quick_clean_sz].arg = 0;
    my_context->quick_cleanups[my_context->quick_clean_sz].a = NULL;
    my_context->quick_cleanups[my_context->quick_clean_sz].dso = NULL;
    my_context->quick_cleanups[my_context->quick_clean_sz++].f = p;
    unlock_cleanup();
}

int AddThreadCleanup(x64emu_t *emu, void *p, void* a, void* dso)
{
    if(!emu)
        return -1;
    if(emu->clean_sz == emu->clean_cap) {
        if(emu->clean_cap > INT_MAX - 8)
            return -1;
        int capacity = emu->clean_cap + 8;
        cleanup_t* entries = (cleanup_t*)box_realloc(emu->cleanups, sizeof(cleanup_t)*capacity);
        if(!entries)
            return -1;
        emu->cleanups = entries;
        emu->clean_cap = capacity;
    }
    lockLibLoader();
    elfheader_t* h = dso ? FindElfAddress(my_context, (uintptr_t)dso) : NULL;
    if(!h)
        h = FindElfAddress(my_context, (uintptr_t)p);
    if(h)
        ++h->tls_dtor_count;
    emu->cleanups[emu->clean_sz].arg = 1;
    emu->cleanups[emu->clean_sz].a = a;
    emu->cleanups[emu->clean_sz].dso = h;
    emu->cleanups[emu->clean_sz++].f = p;
    unlockLibLoader();
    return 0;
}

void CallThreadCleanup(x64emu_t *emu)
{
    if(!emu || !emu->cleanups)
        return;
    printf_log(LOG_DEBUG, "Calling thread_local destructors registered functions\n");
    while(emu->clean_sz) {
        cleanup_t cleanup = emu->cleanups[--emu->clean_sz];
        printf_log(LOG_DEBUG, "Call thread cleanup #%d (args:%d, arg:%p)\n", emu->clean_sz, cleanup.arg, cleanup.a);
        RunFunctionWithEmu(emu, 0, (uintptr_t)cleanup.f, cleanup.arg, cleanup.a);
        // The callback may register more destructors or close its own DSO.
        // Keep its code and dependencies mapped until it has returned.
        ReleaseThreadCleanupDso(cleanup.dso, emu);
    }
    box_free(emu->cleanups);
    emu->cleanups = NULL;
    emu->clean_cap = 0;
}

void CallCleanup(x64emu_t *emu, elfheader_t* h)
{
    printf_log(LOG_DEBUG, "Calling atexit registered functions for elf: %p/%s\n", h, h?h->name:"(nil)");
    if(!h)
        return;
    for(;;) {
        lock_cleanup();
        if(!h->clean_sz) {
            unlock_cleanup();
            break;
        }
        // Remove before calling guest code, which may register or finalize again.
        cleanup_t cleanup = h->cleanups[--h->clean_sz];
        unlock_cleanup();
        RunFunctionWithEmu(emu, 0, (uintptr_t)cleanup.f, cleanup.arg, cleanup.a);
    }
}

void CallAllCleanup(x64emu_t *emu)
{
    printf_log(LOG_DEBUG, "Calling atexit registered functions\n");
    for(;;) {
        lock_cleanup();
        if(!my_context->clean_sz) {
            box_free(my_context->cleanups);
            my_context->cleanups = NULL;
            my_context->clean_cap = 0;
            unlock_cleanup();
            break;
        }
        cleanup_t cleanup = my_context->cleanups[--my_context->clean_sz];
        unlock_cleanup();
        RunFunctionWithEmu(emu, 0, (uintptr_t)cleanup.f, cleanup.arg, cleanup.a);
    }
}

void CallQuickCleanup(x64emu_t *emu, int status)
{
    printf_log(LOG_DEBUG, "Calling at_quick_exit registered functions\n");
    for(;;) {
        lock_cleanup();
        if(!my_context->quick_clean_sz) {
            box_free(my_context->quick_cleanups);
            my_context->quick_cleanups = NULL;
            my_context->quick_clean_cap = 0;
            unlock_cleanup();
            break;
        }
        cleanup_t cleanup = my_context->quick_cleanups[--my_context->quick_clean_sz];
        unlock_cleanup();
        RunFunctionWithEmu(emu, 0, (uintptr_t)cleanup.f, 2, NULL, status);
    }
}
