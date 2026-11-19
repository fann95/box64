// SPDX-License-Identifier: MIT
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdarg.h>
#include <unistd.h>

static ssize_t test_readlink(const char*, char*, size_t);
#define readlink test_readlink
#include "tools/env.c"
#undef readlink

box64context_t* my_context;
int box64_wine, box64_is32bits;
static sem_t first_written, second_written;
static int parallel;

void PrintfFtrace(int prefix, const char* format, ...) {}
void DetectUnityPlayer(char* name) {}
void ParseVolatileMetadata(char* name, void* base) {}
uint32_t getProtection(uintptr_t address) { return 0; }

static ssize_t test_readlink(const char* procpath, char* output, size_t size)
{
    int fd = -1;
    assert(sscanf(procpath, "/proc/self/fd/%d", &fd) == 1);
    if (fd == 18) {
        errno = ENOENT;
        return -1;
    }
    const char* path = fd == 11 ? "/tmp/SECOND-LONGER.so" : "/tmp/FIRST.so";
    if (parallel && fd == 11) assert(sem_wait(&first_written) == 0);
    size_t length = strlen(path);
    assert(length <= size);
    memcpy(output, path, length);
    if (parallel && fd == 10) {
        assert(sem_post(&first_written) == 0);
        assert(sem_wait(&second_written) == 0);
    }
    if (parallel && fd == 11) assert(sem_post(&second_written) == 0);
    return length;
}

static void* record_thread(void* arg)
{
    int fd = (intptr_t)arg;
    RecordEnvMappings(0x300000 + fd * 0x1000, 0x1000, fd);
    return NULL;
}

static int check_mapping(uintptr_t address, const char* expected)
{
    const char* name = NULL;
    int present = IsAddrFileMapped(address, &name, NULL);
    if (expected ? (!present || strcmp(name, expected)) : present) {
        fprintf(stderr, "FAIL: mapping %#lx: expected %s, got %s\n",
                address, expected ? expected : "none", present ? name : "none");
        return 1;
    }
    return 0;
}

int main(void)
{
    box64context_t context = {0};
    my_context = &context;
    assert(pthread_mutex_init(&context.mutex_dyndump, NULL) == 0);
    assert(sem_init(&first_written, 0, 0) == 0);
    assert(sem_init(&second_written, 0, 0) == 0);
    RecordEnvMappings(0x200000, 0x1000, 17);
    RecordEnvMappings(0x210000, 0x1000, 18); // readlink fails after a successful call
    int failures = check_mapping(0x210000, NULL);
    RecordEnvMappings(0x220000, 0x1000, 0); // fd zero is valid too
    failures += check_mapping(0x220000, "/tmp/FIRST.so");
    parallel = 1;
    pthread_t first, second;
    assert(pthread_create(&first, NULL, record_thread, (void*)10) == 0);
    assert(pthread_create(&second, NULL, record_thread, (void*)11) == 0);
    assert(pthread_join(first, NULL) == 0);
    assert(pthread_join(second, NULL) == 0);
    failures += check_mapping(0x30a000, "/tmp/FIRST.so");
    failures += check_mapping(0x30b000, "/tmp/SECOND-LONGER.so");
    mapping_t* mapping;
    kh_foreach_value(mapping_entries, mapping, {
        box_free(mapping->filename);
        box_free(mapping->fullname);
        box_free(mapping);
    });
    kh_destroy(mapping_entry, mapping_entries);
    rbtree_delete(envmap);
    sem_destroy(&first_written);
    sem_destroy(&second_written);
    pthread_mutex_destroy(&context.mutex_dyndump);
    if (!failures) puts("PASS: concurrent mapping paths, failed readlink and fd zero");
    return failures ? 1 : 0;
}
