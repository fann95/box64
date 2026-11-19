// SPDX-License-Identifier: MIT
// Exercise the real wrappers/helpers without changing any host CPU affinity.
#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct x64emu_s { int unused; } x64emu_t;
static struct { uint32_t skipcpu, maxcpu; } settings;
#define BOX64ENV(name) settings.name
#define EXPORT
static uint8_t host_mask[16], passed_mask[16];
static int host_error, failures;

static int fake_getaffinity(pid_t pid, size_t size, cpu_set_t *mask)
{
    (void)pid;
    if (host_error) { errno = EINVAL; return -1; }
    if (size > sizeof(host_mask)) abort();
    memcpy(mask, host_mask, size);
    return 0;
}

static int fake_setaffinity(pid_t pid, size_t size, const cpu_set_t *mask)
{
    (void)pid;
    if (size > sizeof(passed_mask)) abort();
    memcpy(passed_mask, mask, size);
    return 0;
}

static long fake_ptrace(int request, ...) { (void)request; abort(); }
static pid_t fake_waitpid(pid_t pid, int *status, int options) { abort(); }
static int isProcessBox64(pid_t pid) { abort(); }
#define sched_getaffinity fake_getaffinity
#define sched_setaffinity fake_setaffinity
#define ptrace fake_ptrace
#define waitpid fake_waitpid
#include "affinity_functions.inc"

static void check(int good, const char *name, const char *reason)
{
    if (!good) { fprintf(stderr, "FAIL: %s: %s\n", name, reason); ++failures; }
}

typedef int (*affinity_fn)(x64emu_t *, pid_t, size_t, cpu_set_t *);
static void exercise(const char *name, affinity_fn get, affinity_fn set)
{
    uint8_t guest[16], expected[16], original[16];
    settings.skipcpu = 3;
    settings.maxcpu = 5;
    memset(host_mask, 0xff, sizeof(host_mask));
    memset(guest, 0xa5, sizeof(guest));
    memset(expected, 0, sizeof(expected));
    expected[0] = 0x1f; // Host CPUs 3..7 are guest CPUs 0..4.
    check(get(NULL, 0, sizeof(guest), (cpu_set_t *)guest) == 0, name, "get return");
    check(!memcmp(guest, expected, sizeof(guest)), name, "get must limit the shifted host mask");

    memset(guest, 0, sizeof(guest));
    guest[0] = 3; guest[1] = 1; // Guest CPUs 0,1,8: CPU 8 is outside maxcpu.
    memcpy(original, guest, sizeof(guest));
    memset(expected, 0, sizeof(expected)); expected[0] = 0x18;
    check(set(NULL, 0, sizeof(guest), (cpu_set_t *)guest) == 0, name, "set return");
    check(!memcmp(passed_mask, expected, sizeof(expected)), name, "set must send only host CPUs 3,4");
    check(!memcmp(guest, original, sizeof(guest)), name, "set must not modify the caller's input mask");

    host_error = 1;
    memset(guest, 0x5a, sizeof(guest)); memcpy(original, guest, sizeof(guest));
    check(get(NULL, 0, sizeof(guest), (cpu_set_t *)guest) == -1 && errno == EINVAL,
          name, "host failure must propagate");
    check(!memcmp(guest, original, sizeof(guest)), name, "failed get must leave output unchanged");
    host_error = 0;

    settings.skipcpu = 0;
    check(get(NULL, 0, sizeof(guest), (cpu_set_t *)guest) == 0, name, "bypass get return");
    check(!memcmp(guest, host_mask, sizeof(guest)), name, "skipcpu=0 path must remain unchanged");
    check(set(NULL, 0, sizeof(guest), (cpu_set_t *)guest) == 0, name, "bypass set return");
    check(!memcmp(passed_mask, guest, sizeof(guest)), name, "bypass passes mask unchanged");
}

int main(void)
{
    exercise("64-bit wrappers", my_sched_getaffinity, my_sched_setaffinity);
    exercise("32-bit wrappers", my32_sched_getaffinity, my32_sched_setaffinity);
    if (failures) return 1;
    puts("PASS: both affinity wrappers clamp temporary masks and preserve caller input");
    return 0;
}
