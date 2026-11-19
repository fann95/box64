// SPDX-License-Identifier: MIT
// The runner inserts the production loader and allocator functions.
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "dynablock_private.h"

#undef MADV_HUGEPAGE
typedef union { struct { unsigned offs:31, fill:1; }; uint32_t x32; } mark_t;
typedef struct { mark_t prev, next; uint8_t __attribute__((aligned(16))) mark[]; } blockmark_t;
// Only the chunk fields consumed by the extracted functions are needed here.
typedef struct { void* block; size_t size, maxfree; void* first; } blocklist_t;
typedef struct { blocklist_t** chunks; int cap, size, has_new, dirty; } mmaplist_t;
#define NEXT_BLOCK(b) ((blockmark_t*)((uintptr_t)(b)+(b)->next.offs))
#define PREV_BLOCK(b) ((blockmark_t*)((uintptr_t)(b)-(b)->prev.offs))
#define SIZE_BLOCK(b) ((size_t)(b).offs-sizeof(blockmark_t))
#define THRESHOLD (128-1*sizeof(blockmark_t))
#define box_realloc realloc
#define dynarec_log(...) ((void)0)
#define printf_log(...) ((void)0)
#define setProtection_box(...) ((void)0)
#define ClearCache(...) ((void)0)

enum { LIVE, GONE, NOT_DONE, TO_DELETE, LOST, FREE, REJECT, BAD_RELOC, CANCEL_RELOC, ZERO_SIZE };
#define MAX_BLOCKS 16
#define GUEST_BASE 0x10000UL
#define GUEST_DELTA 0x200000UL
static int kinds[MAX_BLOCKS], published[MAX_BLOCKS], accounted, indexed, relocated;
static struct { uintptr_t max_db_size; void* db_sizes; } context;
static typeof(context)* my_context = &context;
static void* rbt_dynmem = (void*)1;
static void* native_next = (void*)2;
static int memory_guard;
static int LockDynablockMemory(void) { assert(!memory_guard); memory_guard=1; return 1; }
static void UnlockDynablockMemory(int token) { assert(token==1 && memory_guard); memory_guard=0; }

static int guest_id(uintptr_t addr)
{
    assert(addr>=GUEST_BASE+GUEST_DELTA);
    int id = (addr-GUEST_BASE-GUEST_DELTA)/0x100;
    assert(id>=0 && id<MAX_BLOCKS);
    return id;
}
static int addJumpTableIfDefault64(void* addr, void* jump)
{
    int id = guest_id((uintptr_t)addr);
    dynablock_t* db = *(dynablock_t**)((char*)jump-sizeof(void*));
    assert(db->jmpnext==jump && db->x64_addr==addr);
    assert(db->done && !db->gone && !db->to_delete && !db->retire_lost);
    if(kinds[id]==REJECT) return 0;
    assert(kinds[id]==LIVE || kinds[id]==CANCEL_RELOC || kinds[id]==ZERO_SIZE);
    assert(!published[id]++);
    return 1;
}
static void rb_inc(void* tree, uintptr_t low, uintptr_t high)
{
    assert(low==16 && high==17);
    ++accounted;
}
static void rb_set_64(void* tree, uintptr_t low, uintptr_t high, uintptr_t value)
{
#ifndef RECLAIM_BASELINE
    assert(memory_guard);
#endif
    assert(tree==rbt_dynmem && low==value && high>low);
    ++indexed;
}
static uintptr_t RelocGetNext(void) { return 0x1234; }
static int ApplyRelocs(dynablock_t* db, intptr_t delta, intptr_t guest_delta, uintptr_t start)
{
    int id = guest_id((uintptr_t)db->x64_addr);
    ++relocated;
    if(kinds[id]==BAD_RELOC) return -1;
    assert(kinds[id]==CANCEL_RELOC);
    // Preserve the existing RELOC_CANCELBLOCK policy: publish dirty for validation.
    db->dirty=1;
    db->hash=0;
    return 0;
}

static blockmark_t* getNextFreeBlock(blockmark_t* mark)
{
    while(mark->next.fill) mark=NEXT_BLOCK(mark);
    return mark;
}
#include "dynacache_reclaim_functions.inc"

static void check_chain(blocklist_t* chunk, int expected_live)
{
    blockmark_t* mark=chunk->block;
    blockmark_t* previous=NULL;
    void* first=NULL;
    size_t maxfree=0;
    int live=0, count=0;
    while(mark->next.offs) {
        assert(++count<=MAX_BLOCKS*2);
        assert((char*)mark>=(char*)chunk->block);
        assert((char*)NEXT_BLOCK(mark)<=(char*)chunk->block+chunk->size-sizeof(blockmark_t));
        if(previous) assert(mark->prev.x32==previous->next.x32);
        else assert(!mark->prev.x32);
        if(mark->next.fill) {
            dynablock_t* db=*(dynablock_t**)mark->mark;
            assert(db->done && !db->gone && !db->to_delete && !db->retire_lost
                && "stale cache allocation must be reusable");
            int id=guest_id((uintptr_t)db->x64_addr);
            assert(published[id]);
            assert(db->actual_block==mark->mark);
            ++live;
        } else {
            if(!first) first=mark;
            if(SIZE_BLOCK(mark->next)>maxfree) maxfree=SIZE_BLOCK(mark->next);
            assert(!previous || previous->next.fill); // Adjacent free marks must coalesce.
        }
        previous=mark;
        mark=NEXT_BLOCK(mark);
    }
    assert(previous && mark->prev.x32==previous->next.x32);
    assert(live==expected_live);
    assert(chunk->first==(first?first:mark));
    assert(chunk->maxfree==maxfree);
}

static void run_case(const int* states, int count, int move)
{
    memset(&context,0,sizeof(context));
    memset(published,0,sizeof(published));
    memcpy(kinds,states,count*sizeof(*states));
    accounted=indexed=relocated=0;
    size_t stride=(sizeof(blockmark_t)+96+sizeof(dynablock_t)+15)&~15UL;
    size_t size=sizeof(blocklist_t)+count*stride+sizeof(blockmark_t);
    blocklist_t* original=calloc(1,size);
    assert(original);
    original->block=original+1;
    original->size=size-sizeof(*original);
    original->first=(char*)original->block+count*stride;
    for(int id=0;id<count;++id) {
        blockmark_t* mark=(void*)((char*)original->block+id*stride);
        mark->next.offs=stride;
        mark->next.fill=1;
        if(id) { mark->prev.offs=stride; mark->prev.fill=1; }
        dynablock_t* db=(void*)(mark->mark+96);
        *db=(dynablock_t){.actual_block=mark->mark,.block=mark->mark+8,
            .jmpnext=mark->mark+48,.x64_addr=(void*)(GUEST_BASE+id*0x100),
            .x64_readaddr=GUEST_BASE+id*0x100,.x64_size=16,.native_size=32,
            .done=1,.in_used=17,.hash=0x12345678};
        *(dynablock_t**)mark->mark=db;
        *(dynablock_t**)((char*)db->jmpnext-8)=db;
        if(states[id]==GONE) db->gone=1;
        if(states[id]==NOT_DONE) db->done=0;
        if(states[id]==TO_DELETE) db->to_delete=1;
        if(states[id]==LOST) db->retire_lost=1;
        if(states[id]==ZERO_SIZE) db->x64_size=0;
        if(states[id]==BAD_RELOC || states[id]==CANCEL_RELOC) {
            db->relocs=mark->mark+80;
            db->relocsize=4;
        }
    }
    blockmark_t* tail=original->first;
    tail->prev.offs=stride;
    tail->prev.fill=1;
    for(int id=0;id<count;++id) if(states[id]==FREE) {
        blockmark_t* mark=(void*)((char*)original->block+id*stride);
        size_t available=freeBlock(original->block,original->size,mark,&original->first);
        if(available>original->maxfree) original->maxfree=available;
    }
    blocklist_t* loaded=original;
    if(move) { loaded=malloc(size); assert(loaded); memcpy(loaded,original,size); }
    mmaplist_t list={0};
    assert(!MmaplistAddBlock_internal(&list,loaded,original,size,GUEST_DELTA,GUEST_BASE+GUEST_DELTA));
    assert(list.size==1 && list.chunks[0]==loaded && indexed==1);
    int live=0, counts=0, relocations=0;
    for(int id=0;id<count;++id) {
        int keep=states[id]==LIVE || states[id]==CANCEL_RELOC || states[id]==ZERO_SIZE;
        assert(published[id]==keep);
        live+=keep;
        counts+=keep && states[id]!=ZERO_SIZE;
        relocations+=states[id]==BAD_RELOC || states[id]==CANCEL_RELOC;
        if(keep) {
            blockmark_t* mark=(void*)((char*)loaded->block+id*stride);
            dynablock_t* db=*(dynablock_t**)mark->mark;
            assert(!db->in_used);
            assert(db->x64_readaddr==GUEST_BASE+GUEST_DELTA+id*0x100);
        }
    }
    assert(accounted==counts && relocated==relocations);
    check_chain(loaded,live);
    if(!live) {
        // Reuse the entire reclaimed chunk with the real allocation/free routines.
        size_t available=loaded->maxfree;
        void* allocation=allocBlock(loaded->block,loaded->first,available,&loaded->first);
        assert(allocation==((blockmark_t*)loaded->block)->mark);
        assert(!((blockmark_t*)loaded->first)->next.offs);
        loaded->maxfree=freeBlock(loaded->block,loaded->size,loaded->block,&loaded->first);
        assert(loaded->maxfree==available);
        check_chain(loaded,0);
    }
    free(list.chunks);
    if(move) free(loaded);
    free(original);
}

int main(void)
{
    const int one_gone[]={GONE};
    const int stale[]={LOST,GONE,NOT_DONE,TO_DELETE,REJECT,BAD_RELOC};
    const int mixed[]={FREE,LOST,FREE,LIVE,GONE,NOT_DONE,FREE,TO_DELETE,LIVE,REJECT,BAD_RELOC,FREE,ZERO_SIZE,CANCEL_RELOC};
    const int live[]={LIVE,LIVE,ZERO_SIZE,CANCEL_RELOC};
    const int free_only[]={FREE,FREE,FREE};
    for(int move=0;move<=1;++move) {
        run_case(one_gone,1,move);
        run_case(stale,sizeof(stale)/sizeof(*stale),move);
        run_case(mixed,sizeof(mixed)/sizeof(*mixed),move);
        run_case(live,sizeof(live)/sizeof(*live),move);
        run_case(free_only,sizeof(free_only)/sizeof(*free_only),move);
    }
    puts("PASS: DynaCache stale/rejected/failed-relocation reclamation, coalescing, relocation, live publication and allocation reuse");
    return 0;
}
