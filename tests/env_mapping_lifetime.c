// SPDX-License-Identifier: MIT
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdarg.h>
#include <unistd.h>

static int test_unlock(pthread_mutex_t*);
#define pthread_mutex_unlock test_unlock
#include "tools/env.c"
#undef pthread_mutex_unlock

box64context_t* my_context;
int box64_wine, box64_is32bits;
static sem_t unlocked, removed;
static _Thread_local int pause_unlock;
static int cache_calls, serialize_checks;

void PrintfFtrace(int prefix, const char* format, ...) {}
void DetectUnityPlayer(char* name) {}
void ParseVolatileMetadata(char* name, void* base) {}
uint32_t getProtection(uintptr_t addr) { return 0; }

static void require_mapping_lock(void)
{
    int result = pthread_mutex_trylock(&my_context->mutex_dyndump);
    if (!result) pthread_mutex_unlock(&my_context->mutex_dyndump);
    assert(result == EBUSY);
}

void MmapDynaCache(mapping_t* mapping)
{
    require_mapping_lock();
    assert(mapping->fullname && mapping->filename);
    ++cache_calls;
}
int MmaplistHasNew(mmaplist_t* list, int clear)
{
    require_mapping_lock();
    ++serialize_checks;
    return 1;
}
void SerializeMmaplist(mapping_t* mapping)
{
    require_mapping_lock();
    assert(mapping->fullname && mapping->filename);
}
void DelMmaplist(mmaplist_t* list) {}

static int test_unlock(pthread_mutex_t* mutex)
{
    int result = pthread_mutex_unlock(mutex);
    if (pause_unlock) {
        pause_unlock = 0;
        assert(sem_post(&unlocked) == 0);
        assert(sem_wait(&removed) == 0);
    }
    return result;
}

static void* record(void* arg)
{
    pause_unlock = 1;
    RecordEnvMappings(0x400000, 4096, (intptr_t)arg);
    return NULL;
}

int main(void)
{
    alarm(10);
    WillRemoveMapping(0x400000, 4096); // no context or mapping during early setup
    box64context_t context = {0};
    my_context = &context;
    box64env.log = 0;
    box64env.dynarec = 1;
    assert(pthread_mutex_init(&context.mutex_dyndump, NULL) == 0);
    WillRemoveMapping(0x400000, 4096); // initialized context, empty mapping tree
    assert(sem_init(&unlocked, 0, 0) == 0);
    assert(sem_init(&removed, 0, 0) == 0);
    int fd = open("/dev/zero", O_RDONLY);
    assert(fd >= 0);
    for (int cache = 0; cache <= 1; ++cache) {
        box64env.dynacache = cache;
        pthread_t thread;
        assert(pthread_create(&thread, NULL, record, (void*)(intptr_t)fd) == 0);
        assert(sem_wait(&unlocked) == 0);
        WillRemoveMapping(0x400000, 4096);
        RemoveMapping(0x400000, 4096);
        assert(sem_post(&removed) == 0);
        assert(pthread_join(thread, NULL) == 0);
    }
    assert(cache_calls == 1 && serialize_checks == 2);
    close(fd);
    kh_destroy(mapping_entry, mapping_entries);
    rbtree_delete(envmap);
    sem_destroy(&unlocked);
    sem_destroy(&removed);
    pthread_mutex_destroy(&context.mutex_dyndump);
    puts("PASS: mapping lifetime survives concurrent removal, with and without DynaCache");
    return 0;
}
