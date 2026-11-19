// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "dynablock_private.h"

typedef union { struct { unsigned offs:31, fill:1; }; uint32_t x32; } mark_t;
typedef struct { mark_t prev, next; uint8_t __attribute__((aligned(16))) mark[]; } blockmark_t;
typedef struct { void* block; size_t size, maxfree; void* first; } blocklist_t;
typedef struct { blocklist_t** chunks; } mmaplist_t;
#define NEXT_BLOCK(b) ((blockmark_t*)((uintptr_t)(b)+(b)->next.offs))
#define SIZE_BLOCK(b) ((size_t)(b).offs-sizeof(blockmark_t))
static blocklist_t chunk;
static void* rbt_dynmem = &chunk;
static int locked, enabled = 1, unloaded, freed;
static dynablock_t* expected;
static int jitProfileActive(void) { return enabled; }
static int LockDynablockMemory(void) { assert(!locked); locked = 1; return 1; }
static void UnlockDynablockMemory(int token) { assert(locked && token == 1); locked = 0; }
static uintptr_t rb_get_64(void* tree, uintptr_t address)
{
    assert(locked && tree == &chunk);
    return address >= (uintptr_t)chunk.block && address < (uintptr_t)chunk.block + chunk.size
        ? (uintptr_t)&chunk : 0;
}
static size_t freeBlock(void* block, size_t size, blockmark_t* mark, void** first)
{
    assert(locked && block == chunk.block && mark == chunk.block && size == chunk.size);
    ++freed;
    return size;
}
static void writeJitProfileUnload(const dynablock_t* db)
{
    assert(locked && db == expected);
    ++unloaded;
}
#include "jit_profile_metadata_lifetime.inc"

int main(void)
{
    size_t page = sysconf(_SC_PAGESIZE);
    uint8_t* memory = mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(memory != MAP_FAILED && !mprotect(memory + page, page, PROT_NONE));
    chunk.block = memory;
    chunk.size = page;
    blockmark_t* mark = chunk.block;
    mark->next.fill = 1;
    mark->next.offs = page - sizeof(*mark);
    uintptr_t allocation = (uintptr_t)mark->mark;
    dynablock_t* db = (dynablock_t*)(memory + 64);
    expected = db;
    db->actual_block = (void*)allocation;
    // Address-only validation must reject wild, truncated and unaligned self pointers.
    uintptr_t candidates[] = {0, 1, UINTPTR_MAX, (uintptr_t)memory + page,
        (uintptr_t)memory + page - sizeof(*mark) - 1, (uintptr_t)db + 1, (uintptr_t)db};
    for(unsigned i = 0; i < sizeof(candidates) / sizeof(*candidates); ++i) {
        *(dynablock_t**)allocation = (dynablock_t*)candidates[i];
        unloaded = freed = 0;
        FreeDynarecMap(allocation);
        assert(freed == 1 && unloaded == (candidates[i] == (uintptr_t)db));
        unloaded = 0;
        locked = 1;
        unload_chunk(&chunk);
        locked = 0;
        assert(unloaded == (candidates[i] == (uintptr_t)db));
    }
    db->actual_block = (void*)(allocation + 16);
    unloaded = 0;
    FreeDynarecMap(allocation);
    locked = 1;
    unload_chunk(&chunk);
    locked = 0;
    assert(!unloaded);
    // Disabled profiling must not inspect a raw self pointer at all.
    enabled = 0;
    *(dynablock_t**)allocation = (dynablock_t*)1;
    FreeDynarecMap(allocation);
    assert(!unloaded);
    munmap(memory, page * 2);
    puts("PASS: production unload hooks reject partial, wild and truncated self pointers");
}
