// SPDX-License-Identifier: MIT
#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <unistd.h>

extern unsigned long my32___fdelt_chk(unsigned long fd);

static void check_rejected(unsigned long fd)
{
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        int nullfd = open("/dev/null", O_WRONLY);
        assert(nullfd >= 0);
        assert(dup2(nullfd, STDERR_FILENO) == STDERR_FILENO);
        close(nullfd);
        my32___fdelt_chk(fd);
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
}

int main(void)
{
    struct rlimit core_limit = {0, 0};
    assert(setrlimit(RLIMIT_CORE, &core_limit) == 0);

    int quiet[2], wakeup[2];
    assert(pipe(quiet) == 0);
    assert(pipe(wakeup) == 0);
    // Keep fd 32 open but unreadable: the old host-sized index selects it.
    int decoy = fcntl(quiet[0], F_DUPFD, 32);
    int ready = fcntl(wakeup[0], F_DUPFD, 64);
    assert(decoy == 32 && ready == 64);
    assert(write(wakeup[1], "x", 1) == 1);

    uint32_t guest_set[32] = {0};
    unsigned long index = my32___fdelt_chk(ready);
    assert(index < 32);
    guest_set[index] |= UINT32_C(1) << (ready % 32);
    fd_set native_set;
    _Static_assert(sizeof(guest_set) == sizeof(native_set), "Linux fd_set size");
    memcpy(&native_set, guest_set, sizeof(native_set));
    struct timeval timeout = {0, 20000};
    int result = select(ready + 1, &native_set, NULL, NULL, &timeout);
    if (result != 1 || !FD_ISSET(ready, &native_set)) {
        fprintf(stderr, "FAIL: fd 64 wakeup lost (word index %lu, select returned %d)\n", index, result);
        return 1;
    }
    close(decoy);
    close(ready);
    close(quiet[0]);
    close(quiet[1]);
    close(wakeup[0]);
    close(wakeup[1]);

    assert(my32___fdelt_chk(0) == 0);
    assert(my32___fdelt_chk(31) == 0);
    assert(my32___fdelt_chk(32) == 1);
    assert(my32___fdelt_chk(63) == 1);
    assert(my32___fdelt_chk(64) == 2);
    assert(my32___fdelt_chk(1023) == 31);
    check_rejected(1024);
    check_rejected(UINT32_MAX);
    puts("PASS: 32-bit fd_set wakes on fd 64; word boundaries and invalid descriptors checked");
    return 0;
}
