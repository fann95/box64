// SPDX-License-Identifier: MIT
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <inttypes.h>

#include "debug.h"
#include "box64context.h"
#include "perfmap.h"

#ifndef _WIN32
#include "elfloader.h"

void writePerfMap(uintptr_t func_addr, uintptr_t code_addr, size_t code_size, const char* inst_name)
{
    char pbuf[1024];
    const char* symbname = getAddrFunctionName(func_addr);
    int n;
    if(!symbname || !strcmp(symbname, "???"))
        n = snprintf(pbuf, sizeof(pbuf), "0x%" PRIx64 " %" PRId64 " 0x%" PRIx64 ":%s\n", code_addr, code_size, func_addr, inst_name);
    else
        n = snprintf(pbuf, sizeof(pbuf), "0x%" PRIx64 " %" PRId64 " %s:%s\n", code_addr, code_size, symbname, inst_name);
    if(n < 0) return;
    if((size_t)n >= sizeof(pbuf)) n = sizeof(pbuf) - 1;
    pbuf[n - 1] = '\n';
    (void)!write(BOX64ENV(dynarec_perf_map_fd), pbuf, n);
}
#else
void writePerfMap(uintptr_t func_addr, uintptr_t code_addr, size_t code_size, const char* inst_name) { }
#endif

#if defined(DYNAREC) && defined(__linux__)
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include "dynarec/dynablock_private.h"

#define JIT_PROFILE_LIMIT (128u * 1024u * 1024u)
#define JIT_PROFILE_RECORD_LIMIT (1024u * 1024u)
#define JIT_PROFILE_ERROR_RESERVE 128u

// Independent of the runtime locks: no allocation, symbol lookup or logging
// while this mutex is held. A nested signal handler fails the profile closed.
static pthread_mutex_t jit_profile_mutex = PTHREAD_MUTEX_INITIALIZER;
static __thread volatile sig_atomic_t jit_profile_entered;
static int jit_profile_state; // 0: uninitialized, 1: enabled, -1: disabled
static int jit_profile_interrupted;
static pid_t jit_profile_pid;
static int jit_profile_fd = -1;
static size_t jit_profile_written;
static uint64_t jit_profile_last_time;
static char jit_profile_record[JIT_PROFILE_RECORD_LIMIT];

static char* jitProfileNumber(char* out, uint64_t number, unsigned base)
{
    static const char digits[] = "0123456789abcdef";
    char reversed[24];
    unsigned n = 0;
    do {
        reversed[n++] = digits[number % base];
        number /= base;
    } while(number);
    while(n)
        *out++ = reversed[--n];
    return out;
}

static int jitProfileTime(uint64_t* result)
{
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC, &now))
        return 0;
    *result = (uint64_t)now.tv_sec * 1000000000u + now.tv_nsec;
    jit_profile_last_time = *result;
    return 1;
}

static int jitProfileWrite(const char* bytes, size_t size)
{
    if(size > JIT_PROFILE_LIMIT - jit_profile_written)
        return 0;
    while(size) {
        // Also cover a fork from a signal handler during an outer hook.
        if(getpid() != __atomic_load_n(&jit_profile_pid, __ATOMIC_ACQUIRE))
            return 0;
        ssize_t n = write(jit_profile_fd, bytes, size);
        if(n < 0 && errno == EINTR)
            continue;
        if(n <= 0)
            return 0;
        bytes += n;
        size -= n;
        jit_profile_written += n;
    }
    return 1;
}

static void jitProfileDisable(const char* reason)
{
    __atomic_store_n(&jit_profile_state, -1, __ATOMIC_RELEASE);
    if(jit_profile_fd >= 0) {
        if(reason) {
            char error[JIT_PROFILE_ERROR_RESERVE];
            char* out = error;
            uint64_t stamp = jit_profile_last_time;
            jitProfileTime(&stamp);
            *out++ = 'E'; *out++ = '\t';
            out = jitProfileNumber(out, stamp, 10);
            *out++ = '\t';
            while(*reason && out < error + sizeof(error) - 1)
                *out++ = *reason++;
            *out++ = '\n';
            jitProfileWrite(error, out - error);
        }
        close(jit_profile_fd);
        jit_profile_fd = -1;
    }
}

static void jitProfileInit(void)
{
    const char* directory = getenv("BOX64_JITPROFILE_DIR");
    if(!directory || !*directory) {
        jitProfileDisable(NULL);
        return;
    }
    char path[PATH_MAX];
    size_t n = strnlen(directory, sizeof(path) - 40);
    if(n == sizeof(path) - 40) {
        jitProfileDisable(NULL);
        return;
    }
    memcpy(path, directory, n);
    char* out = path + n;
    memcpy(out, "/jit-", 5); out += 5;
    out = jitProfileNumber(out, jit_profile_pid, 10);
    memcpy(out, ".maplog", 8);
    jit_profile_fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if(jit_profile_fd < 0) {
        jitProfileDisable(NULL);
        return;
    }
    uint64_t stamp;
    if(!jitProfileTime(&stamp)) {
        jitProfileDisable("clock");
        return;
    }
    out = jit_profile_record;
    memcpy(out, "V\t1\t", 4); out += 4;
    out = jitProfileNumber(out, jit_profile_pid, 10);
    *out++ = '\t';
    out = jitProfileNumber(out, stamp, 10);
    *out++ = '\n';
    if(!jitProfileWrite(jit_profile_record, out - jit_profile_record)) {
        jitProfileDisable("write");
        return;
    }
    __atomic_store_n(&jit_profile_state, 1, __ATOMIC_RELEASE);
}

int jitProfileActive(void)
{
    return __atomic_load_n(&jit_profile_state, __ATOMIC_ACQUIRE) >= 0;
}

static void jitProfileLeave(void)
{
    if(__atomic_load_n(&jit_profile_interrupted, __ATOMIC_ACQUIRE)
        && __atomic_load_n(&jit_profile_state, __ATOMIC_ACQUIRE) >= 0)
        jitProfileDisable("reentrant");
    pthread_mutex_unlock(&jit_profile_mutex);
    jit_profile_entered = 0;
    // A signal may have arrived between the first check and clearing the TLS
    // guard. After clearing it, nested hooks can acquire the mutex themselves.
    if(__atomic_load_n(&jit_profile_interrupted, __ATOMIC_ACQUIRE)
        && __atomic_load_n(&jit_profile_state, __ATOMIC_ACQUIRE) >= 0) {
        jit_profile_entered = 1;
        pthread_mutex_lock(&jit_profile_mutex);
        jitProfileDisable("reentrant");
        pthread_mutex_unlock(&jit_profile_mutex);
        jit_profile_entered = 0;
    }
}

static int jitProfileEnter(void)
{
    pid_t pid = getpid();
    pid_t owner = 0;
    __atomic_compare_exchange_n(&jit_profile_pid, &owner, pid, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    if(owner && owner != pid) {
        // Never take an inherited mutex or write the parent's descriptor.
        __atomic_store_n(&jit_profile_state, -1, __ATOMIC_RELEASE);
        return 0;
    }
    if(jit_profile_entered) {
        __atomic_store_n(&jit_profile_interrupted, 1, __ATOMIC_RELEASE);
        return 0;
    }
    jit_profile_entered = 1;
    pthread_mutex_lock(&jit_profile_mutex);
    if(!__atomic_load_n(&jit_profile_state, __ATOMIC_ACQUIRE))
        jitProfileInit();
    if(__atomic_load_n(&jit_profile_interrupted, __ATOMIC_ACQUIRE)
        && __atomic_load_n(&jit_profile_state, __ATOMIC_ACQUIRE) >= 0)
        jitProfileDisable("reentrant");
    if(__atomic_load_n(&jit_profile_state, __ATOMIC_ACQUIRE) < 0) {
        jitProfileLeave();
        return 0;
    }
    return 1;
}

static void jitProfileCommit(size_t size)
{
    if(__atomic_load_n(&jit_profile_interrupted, __ATOMIC_ACQUIRE))
        jitProfileDisable("reentrant");
    else if(size > JIT_PROFILE_LIMIT - JIT_PROFILE_ERROR_RESERVE - jit_profile_written)
        jitProfileDisable("limit");
    else if(!jitProfileWrite(jit_profile_record, size))
        jitProfileDisable("write");
}

// Return the complete encoded table length, including the terminator. A zero
// following a saturated nibble finishes that instruction; it is not the final
// terminator (addInst emits it for exact multiples of fifteen).
static size_t jitProfileInstSize(const dynablock_t* db)
{
    uintptr_t start = (uintptr_t)db->actual_block;
    uintptr_t native = (uintptr_t)db->block;
    uintptr_t table = (uintptr_t)db->instsize;
    uintptr_t end = start + (db->size > 0 ? db->size : 0);
    uintptr_t stop = (uintptr_t)db;
    if(!start || end <= start || stop < start || stop > end
        || sizeof(*db) > end - stop || native < start || native > end
        || db->native_size > end - native || db->prefixsize > db->native_size
        || table < native + db->native_size || table >= stop
        || db->x64_size > UINTPTR_MAX - (uintptr_t)db->x64_addr)
        return 0;
    if(db->arch && (uintptr_t)db->arch >= table && (uintptr_t)db->arch < stop)
        stop = (uintptr_t)db->arch;
    if(db->callrets && (uintptr_t)db->callrets >= table && (uintptr_t)db->callrets < stop)
        stop = (uintptr_t)db->callrets;
    size_t available = stop - table;
    if(available > (JIT_PROFILE_RECORD_LIMIT - 256) / 2)
        available = (JIT_PROFILE_RECORD_LIMIT - 256) / 2;
    size_t guest = 0, native_size = db->prefixsize;
    int continuation = 0;
    for(size_t i = 0; i < available; ++i) {
        unsigned x64 = db->instsize[i].x64, nat = db->instsize[i].nat;
        if(!x64 && !nat && !continuation)
            // x64_size covers the hashed source range, including trailing dead
            // code removed before emission. Only the emitted prefix has entries.
            return guest && guest <= db->x64_size ? i + 1 : 0;
        if(x64 > db->x64_size - guest || nat * 4 > db->native_size - native_size)
            return 0;
        guest += x64;
        native_size += nat * 4;
        continuation = x64 == 15 || nat == 15;
    }
    return 0;
}

static void jitProfileEvent(const dynablock_t* db, int load)
{
    if(!jitProfileActive())
        return;
    int saved_errno = errno;
    if(!jitProfileEnter()) {
        errno = saved_errno;
        return;
    }
    // Empty interpreter stubs do not carry guest instruction mappings.
    if(db && db->native_size && db->x64_size) {
        uint64_t stamp;
        size_t count = load ? jitProfileInstSize(db) : 0;
        if(load && !count) {
            jitProfileDisable("metadata");
        } else if(!jitProfileTime(&stamp)) {
            jitProfileDisable("clock");
        } else {
            char* out = jit_profile_record;
            *out++ = load ? 'L' : 'U'; *out++ = '\t';
            out = jitProfileNumber(out, stamp, 10);
            *out++ = '\t';
            out = jitProfileNumber(out, (uintptr_t)db->block, 16);
            *out++ = '\t';
            out = jitProfileNumber(out, db->native_size, 16);
            if(load) {
                *out++ = '\t';
                out = jitProfileNumber(out, (uintptr_t)db->x64_addr, 16);
                *out++ = '\t';
                out = jitProfileNumber(out, db->x64_size, 16);
                *out++ = '\t';
                out = jitProfileNumber(out, db->prefixsize, 16);
                *out++ = '\t';
                static const char hex[] = "0123456789abcdef";
                for(size_t i = 0; i < count; ++i) {
                    // Specify the on-disk nibble order independently of ABI.
                    *out++ = hex[db->instsize[i].nat];
                    *out++ = hex[db->instsize[i].x64];
                }
            }
            *out++ = '\n';
            jitProfileCommit(out - jit_profile_record);
        }
    }
    jitProfileLeave();
    errno = saved_errno;
}

void writeJitProfileLoad(const struct dynablock_s* block)
{
    jitProfileEvent(block, 1);
}

void writeJitProfileUnload(const struct dynablock_s* block)
{
    jitProfileEvent(block, 0);
}
#else
int jitProfileActive(void) { return 0; }
void writeJitProfileLoad(const struct dynablock_s* block) { }
void writeJitProfileUnload(const struct dynablock_s* block) { }
#endif
