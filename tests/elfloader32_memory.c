// SPDX-License-Identifier: MIT
// Native regression harness for the real Box32 ELF reservation code.
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "box64context.h"
#include "debug.h"
#include "custommem.h"
#include "rbtree.h"
#include "elfs/elfloader_private.h"

#define BASE 0x60000000UL
#define LIMIT 0x100000000ULL

box64env_t box64env;
uintptr_t box64_pagesize;
box64context_t* my_context;
static rbtree_t* mappings;
static pthread_mutex_t allocation_mutex = PTHREAD_MUTEX_INITIALIZER;
static const char* scenario;
static unsigned map_calls;

int AllocLoadElfMemory32(box64context_t*, elfheader_t*, int);

void PrintfFtrace(int prefix, const char* format, ...)
{
    (void)prefix;
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

void box64_abort(void) { _exit(126); }
void* customMalloc(size_t size) { return malloc(size); }
void customFree(void* pointer) { free(pointer); }
void lockMmapMutex(void) { assert(!pthread_mutex_lock(&allocation_mutex)); }
void unlockMmapMutex(void) { assert(!pthread_mutex_unlock(&allocation_mutex)); }

void loadProtectionFromMap(void)
{
    FILE* maps = fopen("/proc/self/maps", "r");
    assert(maps);
    char line[1024];
    unsigned long start, end;
    while(fgets(line, sizeof(line), maps))
        if(sscanf(line, "%lx-%lx", &start, &end) == 2)
            rb_set(mappings, start, end, 1);
    fclose(maps);
}

void* find31bitBlockNearHint(void* hint, size_t size, uintptr_t mask)
{
    uintptr_t result;
    if(!strcmp(scenario, "exhausted"))
        return NULL;
    if(rb_find_free_range(mappings, hint ? (uintptr_t)hint : BASE,
                         BASE + 0x1000000, size, mask, &result))
        return (void*)result;
    return NULL;
}

void* find31bitBlockElf(size_t size, int mainbin, uintptr_t mask)
{
    (void)mainbin;
    return find31bitBlockNearHint((void*)BASE, size, mask);
}

void* InternalMmap(void* address, unsigned long length, int prot, int flags, int fd, ssize_t offset)
{
    ++map_calls;
    if(!strcmp(scenario, "failed")) {
        errno = ENOMEM;
        return MAP_FAILED;
    }
    if(!strcmp(scenario, "high"))
        return (void*)syscall(SYS_mmap, NULL, length, prot, flags, fd, offset);
    if(!strcmp(scenario, "crossing"))
        return (void*)syscall(SYS_mmap, (void*)(LIMIT - box64_pagesize), length,
                             prot, flags | MAP_FIXED_NOREPLACE, fd, offset);
    if(!strcmp(scenario, "collision") && map_calls == 1) {
        void* occupied = (void*)syscall(SYS_mmap, address, length, PROT_NONE,
                                      flags | MAP_FIXED_NOREPLACE, fd, offset);
        assert(occupied == address);
    }
    return (void*)syscall(SYS_mmap, address, length, prot, flags, fd, offset);
}

int InternalMunmap(void* address, unsigned long length)
{
    return syscall(SYS_munmap, address, length);
}

void* __wrap_mmap(void* address, size_t length, int prot, int flags, int fd, off_t offset)
{
    void* result = InternalMmap(address, length, prot, flags, fd, offset);
    if(result != MAP_FAILED)
        rb_set(mappings, (uintptr_t)result, ALIGN((uintptr_t)result + length), 1);
    return result;
}

int __wrap_munmap(void* address, size_t length)
{
    int result = InternalMunmap(address, length);
    if(!result)
        rb_unset(mappings, (uintptr_t)address, ALIGN((uintptr_t)address + length));
    return result;
}

void setProtection_elf(uintptr_t address, size_t size, uint32_t prot)
{
    (void)prot;
    rb_set(mappings, address, ALIGN(address + size), 1);
}

uint32_t getProtection(uintptr_t address) { (void)address; return 0; }
int AddTLSPartition(box64context_t* context, int size) { (void)context; assert(!size); return 0; }
void RecordEnvMappings(uintptr_t address, size_t length, int fd) { (void)address; (void)length; (void)fd; }
void PatchLoadedDynamicSection(elfheader_t* header) { (void)header; }

int main(int argc, char** argv)
{
    assert(argc == 2);
    scenario = argv[1];
    box64_pagesize = sysconf(_SC_PAGESIZE);
    mappings = rbtree_init("elfloader32 test");
    box64env.log = LOG_INFO;

    unsigned char* guard = NULL;
    if(!strcmp(scenario, "gap") || !strcmp(scenario, "hint")) {
        guard = (void*)syscall(SYS_mmap, (void*)(BASE + 10 * box64_pagesize),
                             box64_pagesize, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        assert(guard == (void*)(BASE + 10 * box64_pagesize));
        *guard = 0x5a;
    }
    if(!strcmp(scenario, "hint"))
        box64env.load_addr = BASE;

    box64context_t context = {0};
    elfheader_t header = {0};
    header.name = "elfloader32-regression.so";
    header.memsz = guard ? 9 * box64_pagesize + 0x100 : box64_pagesize;
    header.align = box64_pagesize;
    header.file = tmpfile();
    assert(header.file);
    header.fileno = fileno(header.file);
    if(!strcmp(scenario, "fixed"))
        header.vaddr = BASE + 3;

    int result = AllocLoadElfMemory32(&context, &header, 0);
    int expected_failure = !strcmp(scenario, "failed") || !strcmp(scenario, "exhausted")
                        || !strcmp(scenario, "high") || !strcmp(scenario, "crossing");
    assert((result != 0) == expected_failure);
    if(!result) {
        assert(header.raw && (uintptr_t)header.raw < LIMIT);
        assert(header.raw_size <= LIMIT - (uintptr_t)header.raw);
        assert(header.image && (uintptr_t)header.image < LIMIT);
        if(guard) {
            assert(*guard == 0x5a);
            assert((uintptr_t)header.raw >= BASE + 11 * box64_pagesize);
        }
        if(!strcmp(scenario, "fixed"))
            assert(header.image == (void*)(BASE + 3));
        if(!strcmp(scenario, "collision"))
            assert(map_calls >= 2);
    }
    assert(!pthread_mutex_trylock(&allocation_mutex));
    assert(!pthread_mutex_unlock(&allocation_mutex));
    printf("PASS: %s\n", scenario);
    return 0;
}
