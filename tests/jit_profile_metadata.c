// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "perfmap.h"

static int injection, calls;
static struct dynablock_s* test_block;
static ssize_t injected_write(int fd, const void* bytes, size_t count)
{
    ++calls;
    if(injection == 1 && calls % 3 == 1) {
        errno = EINTR;
        return -1;
    }
    if(injection == 2 && ((const char*)bytes)[0] == 'L') {
        injection = 0;
        errno = ENOSPC;
        return -1;
    }
    if(injection == 3 && ((const char*)bytes)[0] == 'L') {
        injection = 0;
        writeJitProfileUnload(test_block);
    }
    if(injection == 1 && count > 7) count = 7;
    return syscall(SYS_write, fd, bytes, count);
}
#define write injected_write
#include "../src/os/perfmap.c"
#undef write

static void check_errno(int load)
{
    errno = EDOM;
    if(load) writeJitProfileLoad(test_block);
    else writeJitProfileUnload(test_block);
    assert(errno == EDOM);
}

static void* concurrent(void* ignored)
{
    for(int i = 0; i < 50; ++i) check_errno(1);
    return NULL;
}

int main(int argc, char** argv)
{
    assert(argc == 3);
    const char* mode = argv[1];
    assert(!setenv("BOX64_JITPROFILE_DIR", argv[2], 1));
    static uint64_t allocation[256];
    dynablock_t* db = (dynablock_t*)((char*)allocation + 512);
    db->actual_block = allocation;
    db->block = (char*)allocation + sizeof(void*);
    db->size = sizeof(allocation);
    db->native_size = 80;
    db->prefixsize = 4;
    db->x64_addr = (void*)0x400000;
    db->x64_size = 20;
    db->instsize = (instsize_t*)((char*)allocation + 256);
    db->instsize[0] = (instsize_t){.x64=4, .nat=2};
    db->instsize[1] = (instsize_t){.x64=15, .nat=15};
    db->instsize[2] = (instsize_t){0};
    db->instsize[3] = (instsize_t){.x64=1, .nat=1};
    db->instsize[4] = (instsize_t){0};
    test_block = db;
    char path[4096];
    snprintf(path, sizeof(path), "%s/jit-%ld.maplog", argv[2], (long)getpid());
    if(!strcmp(mode, "off")) {
        unsetenv("BOX64_JITPROFILE_DIR");
        check_errno(1);
        assert(!setenv("BOX64_JITPROFILE_DIR", argv[2], 1));
        check_errno(1);
        assert(!jitProfileActive() && access(path, F_OK));
        return 0;
    }
    if(!strcmp(mode, "exclusive")) {
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        assert(fd >= 0 && write(fd, "keep", 4) == 4);
        close(fd);
        check_errno(1);
        assert(!jitProfileActive());
        return 0;
    }
    if(!strcmp(mode, "symlink")) {
        assert(!symlink("untouched", path));
        check_errno(1);
        assert(!jitProfileActive());
        return 0;
    }
    if(!strcmp(mode, "short")) injection = 1;
    if(!strcmp(mode, "failure")) injection = 2;
    if(!strcmp(mode, "reentrant")) injection = 3;
    if(!strcmp(mode, "invalid")) db->instsize = (instsize_t*)((char*)allocation + sizeof(allocation));
    if(!strcmp(mode, "guest_bounds")) db->x64_size = 19;
    if(!strcmp(mode, "dead_tail")) db->x64_size = 70;
    if(!strcmp(mode, "native_bounds")) db->native_size = 72;
    if(!strcmp(mode, "unterminated")) db->arch = db->instsize + 4;
    check_errno(1);
    if(!strcmp(mode, "failure") || !strcmp(mode, "reentrant") || !strcmp(mode, "invalid")
        || !strcmp(mode, "guest_bounds") || !strcmp(mode, "native_bounds")
        || !strcmp(mode, "unterminated")) {
        assert(!jitProfileActive());
        return 0;
    }
    assert(jit_profile_fd >= 0);
    struct stat status;
    assert(!fstat(jit_profile_fd, &status));
    assert((status.st_mode & 0777) == 0600);
    assert(fcntl(jit_profile_fd, F_GETFD) & FD_CLOEXEC);
    if(!strcmp(mode, "cap")) {
        jit_profile_written = JIT_PROFILE_LIMIT - JIT_PROFILE_ERROR_RESERVE - 8;
        assert(lseek(jit_profile_fd, jit_profile_written, SEEK_SET) == jit_profile_written);
        check_errno(1);
        assert(!jitProfileActive());
        assert(!stat(path, &status));
        assert(status.st_size <= JIT_PROFILE_LIMIT);
        return 0;
    }
    if(!strcmp(mode, "fork")) {
        off_t before = status.st_size;
        // The child must refuse the inherited descriptor before trying this lock.
        assert(!pthread_mutex_lock(&jit_profile_mutex));
        pid_t child = fork();
        assert(child >= 0);
        if(!child) {
            check_errno(1);
            check_errno(0);
            _exit(jitProfileActive() ? 1 : 0);
        }
        int result;
        assert(waitpid(child, &result, 0) == child && result == 0);
        assert(!pthread_mutex_unlock(&jit_profile_mutex));
        assert(!fstat(jit_profile_fd, &status) && status.st_size == before);
    }
    if(!strcmp(mode, "threads")) {
        pthread_t threads[4];
        for(int i = 0; i < 4; ++i) assert(!pthread_create(&threads[i], NULL, concurrent, NULL));
        for(int i = 0; i < 4; ++i) assert(!pthread_join(threads[i], NULL));
    }
    check_errno(0);
    db->x64_addr = (void*)0x500000;
    check_errno(1);
    check_errno(0);
    assert(jitProfileActive());
    return 0;
}
