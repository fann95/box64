// SPDX-License-Identifier: MIT
// Production functions are inserted by the runner; allocator/locks are observable.
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <sanitizer/asan_interface.h>
#include "dynablock_private.h"

#define DB_ZOMBIE_SIZE 4
#define BLOCKS 24
#define MAPS 3
#define BOX64ENV(x) 1
#define dynarec_log(...) ((void)0)
#define printf_log(...) warning_hook()
#define box_malloc malloc
#define box_free free
#define native_lock_get_d(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
typedef union { struct { unsigned offs:31, fill:1; }; uint32_t x32; } mark_t;
typedef struct { mark_t prev, next; uint8_t __attribute__((aligned(16))) mark[]; } blockmark_t;
typedef struct { void* block; size_t size, maxfree; void* first; } blocklist_t;
typedef struct { int size; blocklist_t** chunks; } mmaplist_t;
#define NEXT_BLOCK(b) ((blockmark_t*)((uintptr_t)(b)+(b)->next.offs))
#define PREV_BLOCK(b) ((blockmark_t*)((uintptr_t)(b)-(b)->prev.offs))
#define SIZE_BLOCK(b) ((size_t)(b).offs-sizeof(blockmark_t))
static struct {
    pthread_mutex_t mutex_dyndump;
    uintptr_t max_db_size;
    void* db_sizes;
    dynablock_t* db_zombie[DB_ZOMBIE_SIZE];
    int db_zombie_head, db_zombie_count;
    dynablock_t** db_orphan;
    int db_orphan_count, db_orphan_size;
} context;
static typeof(context)* my_context = &context;
static pthread_mutex_t mutex_prot;
static _Thread_local int holds_dyndump, holds_prot, role, critical_depth;
static int setting_prot;
static blocklist_t* maps[MAPS];
static uintptr_t map_start[MAPS], map_end[MAPS];
static int present[MAPS], released[BLOCKS], marked_current[BLOCKS], release_count, tree_visits, size_decrements;
static dynablock_t *blocks[BLOCKS], *published[BLOCKS];
static void* rbt_dynmem = (void*)1;
static void* mapallmem = (void*)2;
static int box64_is32bits;
#define MEM_RESERVED 1
static uint32_t lost_dynablocks_pending;
static sem_t jit_locked, mark_locked, checked_old, old_freed, removal_waiting, memory_waiting, free_waiting;
static int force_free_race, force_mark_during_scan, delayed_id;

static int id_of(dynablock_t* db) { return ((uintptr_t)db->x64_addr-0x1000)/16; }
static int lock_mutex(pthread_mutex_t* mutex)
{
    if (role==3 && mutex==&context.mutex_dyndump) sem_post(&removal_waiting);
    if (role==4 && mutex==&mutex_prot) sem_post(&memory_waiting);
    if (role==5 && mutex==&context.mutex_dyndump) sem_post(&free_waiting);
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 2;
    int error = pthread_mutex_timedlock(mutex, &deadline);
    if (error==EDEADLK && mutex==&mutex_prot) return error;
    if (error) {
        fprintf(stderr, "lock cycle: role=%d error=%d prot=%d dyndump=%d\n",
                role, error, holds_prot, holds_dyndump);
        exit(1);
    }
    if (mutex == &mutex_prot) holds_prot = 1;
    else holds_dyndump = 1;
    return 0;
}
static void unlock_mutex(pthread_mutex_t* mutex)
{
    if (mutex == &mutex_prot) holds_prot = 0;
    else holds_dyndump = 0;
    assert(!pthread_mutex_unlock(mutex));
}
#define mutex_lock lock_mutex
#define mutex_unlock unlock_mutex
static void enter_critical_section(void) { ++critical_depth; }
static void leave_critical_section(void) { assert(critical_depth>0); --critical_depth; }
#define LOCK_PROT() do { enter_critical_section(); assert(!mutex_lock(&mutex_prot)); } while(0)
#define UNLOCK_PROT() do { mutex_unlock(&mutex_prot); leave_critical_section(); } while(0)
static void warning_hook(void)
{
    if (role == 2 && force_free_race) {
        sem_post(&checked_old);
        sem_wait(&old_freed);
    }
}
static dynablock_t* getDB(uintptr_t addr)
{ return __atomic_load_n(&published[(addr-0x1000)/16], __ATOMIC_ACQUIRE); }
static int setJumpTableIfRef64(void* addr, void* jump, void* ref)
{
    dynablock_t* db = getDB((uintptr_t)addr);
    int success = db && (db->block == ref || db->jmpnext == jump);
    if (success) ++marked_current[id_of(db)];
    return success;
}
static void setJumpTableDefault64(void* addr)
{ __atomic_store_n(&published[((uintptr_t)addr-0x1000)/16], NULL, __ATOMIC_RELEASE); }
static void FreeDynablockGdbJIT(dynablock_t* db) {} // Normal non-GDBJIT build.
static uint32_t rb_dec(void* tree, uintptr_t a, uintptr_t b)
{ assert(holds_dyndump); ++size_decrements; return 1; }
static uintptr_t rb_get_rightmost(void* tree) { return 16; }
static uint64_t rb_get_64(void* tree, uintptr_t addr)
{
    assert(tree==rbt_dynmem && holds_prot);
    for(int i=0;i<MAPS;++i)
        if(present[i] && addr>=map_start[i] && addr<map_end[i]) return (uintptr_t)maps[i];
    return 0;
}
static uintptr_t rb_get_leftmost(void* tree)
{
    assert(holds_dyndump);
    uintptr_t start = UINTPTR_MAX;
    for (int i=0; i<MAPS; ++i) if (present[i] && map_start[i]<start) start=map_start[i];
    return start;
}
static void DeferLostDynablock(dynablock_t* db);
static int rb_get_end_64(void* tree, uintptr_t cur, uint64_t* value, uintptr_t* end)
{
    assert(holds_dyndump);
    ++tree_visits;
    if (force_mark_during_scan && cur >= map_end[0]) {
        force_mark_during_scan = 0;
        DeferLostDynablock(blocks[delayed_id]); // Already-scanned chunk: retain pending work.
    }
    uintptr_t next = UINTPTR_MAX;
    for (int i=0; i<MAPS; ++i) if (present[i]) {
        if (cur >= map_start[i] && cur < map_end[i]) {
            *end=map_end[i]; *value=(uintptr_t)maps[i]; return 1;
        }
        if (map_start[i]>cur && map_start[i]<next) next=map_start[i];
    }
    *end = next; *value = 0; return 0;
}
static void rb_unset(void* tree, uintptr_t start, uintptr_t end)
{
    assert(holds_dyndump);
    if (tree != rbt_dynmem) { assert(holds_prot); return; }
    assert(holds_prot);
    for (int i=0; i<MAPS; ++i) if (present[i] && start<map_end[i] && end>map_start[i]) {
        if (start<=map_start[i] && end>=map_end[i]) present[i]=0;
        else if (end>=map_end[i]) map_end[i]=start; // Preserve an omitted header interval.
        else if (start<=map_start[i]) map_start[i]=end;
        else assert(!"unused interior split");
    }
}
static void rb_set(void* tree, uintptr_t start, uintptr_t end, int flags) { assert(!"unused reservation"); }
static void* InternalMmap(void* addr, size_t size, int prot, int flags, int fd, size_t offset)
{ assert(!"unused reservation"); return MAP_FAILED; }
static int InternalMunmap(void* addr, size_t size)
{ assert(holds_dyndump && holds_prot); free(addr); return 0; }
static int cleanDBFromAddressRange_internal(uintptr_t addr, size_t size, int destroy, int locked)
{ assert(holds_dyndump && destroy==1 && locked==1); return 0; }
static size_t freeBlock(void* block, size_t size, blockmark_t* mark, void** first);
static void QueueZombieDynablock(dynablock_t* db);
static void RetireLostDynablocks(void);
static void MarkDynablock(dynablock_t* db);
#include "lost_functions.inc"

static size_t freeBlock(void* block, size_t size, blockmark_t* mark, void** first)
{
    assert(holds_dyndump && holds_prot);
    dynablock_t* db = *(dynablock_t**)mark->mark;
    int id = id_of(db);
    assert(!released[id]++);
    ++release_count;
    assert(mark->next.fill);
    size_t available=actual_freeBlock(block,size,mark,first);
    // Model a physically inaccessible retired allocation, not only a queue entry.
    __asan_poison_memory_region(db,sizeof(*db));
    return available;
}

static void init_maps(void)
{
    size_t stride = (sizeof(blockmark_t)+16+sizeof(dynablock_t)+15)&~15UL;
    for (int m=0; m<MAPS; ++m) {
        size_t count = BLOCKS/MAPS;
        size_t size = count*stride+sizeof(blockmark_t);
        maps[m] = calloc(1, sizeof(blocklist_t)+size);
        maps[m]->size = size;
        maps[m]->block = maps[m]+1;
        maps[m]->first = (char*)maps[m]->block+count*stride;
        map_start[m]=(uintptr_t)maps[m]; map_end[m]=map_start[m]+sizeof(blocklist_t)+size;
        present[m] = 1;
        for (int n=0; n<count; ++n) {
            int id = m*count+n;
            blockmark_t* mark = (blockmark_t*)((char*)maps[m]->block+n*stride);
            mark->next.offs = stride; mark->next.fill = 1;
            if (n) { mark->prev.offs = stride; mark->prev.fill = 1; }
            dynablock_t* db = (dynablock_t*)(mark->mark+16);
            *(dynablock_t**)mark->mark = db;
            *db = (dynablock_t){.actual_block=mark->mark, .block=mark->mark,
                .jmpnext=mark->mark+8, .x64_addr=(void*)(uintptr_t)(0x1000+id*16),
                .x64_size=16, .size=16, .done=1};
            blocks[id] = published[id] = db;
        }
        blockmark_t* tail = (blockmark_t*)((char*)maps[m]->block+count*stride);
        tail->prev.offs = stride; tail->prev.fill = 1;
    }
}
static void* compiler_thread(void* arg)
{
    role=1; mutex_lock(&context.mutex_dyndump);
    sem_post(&jit_locked); sem_wait(&mark_locked);
    mutex_lock(&mutex_prot); mutex_unlock(&mutex_prot);
    RetireLostDynablocks(); mutex_unlock(&context.mutex_dyndump);
    return NULL;
}
static void* marker_thread(void* arg)
{
    role=2; sem_wait(&jit_locked); LOCK_PROT(); sem_post(&mark_locked);
    MarkDynablock(blocks[0]); UNLOCK_PROT();
    return NULL;
}
static void* concurrent_marker(void* arg)
{
    role=2;
    if(arg) LOCK_PROT();
    MarkDynablock(blocks[1]);
    if(arg) UNLOCK_PROT();
    assert(!holds_prot && !critical_depth);
    return NULL;
}
static void* remove_mapping_thread(void* arg)
{
    role=3; DelMmaplist(arg); return NULL;
}

static void original_cases(void)
{
    // A pending request restored from disk must neither publish nor decrement a
    // size count belonging to some other block in the new process.
    published[23]=NULL; blocks[23]->retire_lost=1;
    normalize_loaded_retirement(blocks[23]);
    assert(blocks[23]->gone && !blocks[23]->done && !blocks[23]->retire_lost);
    lost_dynablocks_pending=1; mutex_lock(&context.mutex_dyndump);
    RetireLostDynablocks(); assert(!size_decrements && !context.db_zombie_count);
    mutex_unlock(&context.mutex_dyndump);
    // Deterministic ABBA: compiler holds dyndump and needs prot; marker owns prot.
    published[0] = NULL;
    pthread_t jit, marker; pthread_create(&jit,NULL,compiler_thread,NULL);
    pthread_create(&marker,NULL,marker_thread,NULL); pthread_join(jit,NULL); pthread_join(marker,NULL);
    assert(blocks[0]->gone && context.db_zombie_count==1);
    // The same branch must not recursively lock dyndump.
    mutex_lock(&context.mutex_dyndump); published[2]=NULL; MarkDynablock(blocks[2]);
    assert(!blocks[2]->gone); RetireLostDynablocks(); assert(blocks[2]->gone);
    mutex_unlock(&context.mutex_dyndump);
    // Ordinary invalidation consumes a pending request without double retirement.
    published[1]=NULL; MarkDynablock(blocks[1]);
    mutex_lock(&context.mutex_dyndump); FreeDynablock(blocks[1],0,0); RetireLostDynablocks();
    assert(context.db_zombie_count==3); // No double retirement.
    // Publication winning before the drain must retain the now-current block.
    published[3]=NULL; MarkDynablock(blocks[3]); published[3]=blocks[3];
    RetireLostDynablocks(); assert(!blocks[3]->gone && marked_current[3]==1);
    // A mark arriving after its chunk was scanned remains pending for the next pass.
    published[4]=NULL; published[8]=NULL; MarkDynablock(blocks[8]);
    delayed_id=4; force_mark_during_scan=1; RetireLostDynablocks();
    assert(!blocks[4]->gone && lost_dynablocks_pending); RetireLostDynablocks();
    assert(blocks[4]->gone);
    // No retained raw pointer into a mapping survives its complete removal.
    mmaplist_t* removed=calloc(1,sizeof(*removed));
    removed->size=1; removed->chunks=malloc(sizeof(*removed->chunks)); removed->chunks[0]=maps[2];
    pthread_t removal; pthread_create(&removal,NULL,remove_mapping_thread,removed);
    sem_wait(&removal_waiting); // Removal is now blocked on the scanner's dyndump ownership.
    lost_dynablocks_pending=1; RetireLostDynablocks(); assert(present[2]);
    published[16]=NULL; MarkDynablock(blocks[16]);
    mutex_unlock(&context.mutex_dyndump); pthread_join(removal,NULL);
    // Pointer membership must be checked before reading an unmapped dynablock.
    MarkDynablock(blocks[16]);
    FreeDynablock(blocks[16],1,0);
    FreeInvalidDynablock(blocks[16],1);
    mutex_lock(&context.mutex_dyndump);
    RetireLostDynablocks(); assert(!present[2]);
    // Fill/evict the real production zombie ring while scanning adjacent allocations.
    for (int id=3; id<16; ++id) if (!released[id] && !blocks[id]->gone) {
        published[id]=NULL; MarkDynablock(blocks[id]);
    }
    RetireLostDynablocks(); FlushZombieDynablocks();
    assert(release_count==16 && size_decrements==16);
    for (int id=0; id<16; ++id) assert(released[id]==1);
    int visits=tree_visits; RetireLostDynablocks(); assert(visits==tree_visits);
    mutex_unlock(&context.mutex_dyndump);
}

static void reset_case(void)
{
    assert(!holds_dyndump && !holds_prot && !critical_depth && !setting_prot);
    for(int i=0;i<MAPS;++i) if(present[i]) free(maps[i]);
    free(context.db_orphan);
    context.db_orphan=NULL;
    context.db_orphan_count=context.db_orphan_size=0;
    context.db_zombie_head=context.db_zombie_count=0;
    context.max_db_size=0;
    memset(context.db_zombie,0,sizeof(context.db_zombie));
    memset(present,0,sizeof(present));
    memset(released,0,sizeof(released));
    memset(marked_current,0,sizeof(marked_current));
    release_count=tree_visits=size_decrements=0;
    lost_dynablocks_pending=0;
    force_free_race=force_mark_during_scan=0;
    sem_t* sems[]={&jit_locked,&mark_locked,&checked_old,&old_freed,&removal_waiting,&memory_waiting,&free_waiting};
    for(size_t i=0;i<sizeof(sems)/sizeof(*sems);++i)
        while(!sem_trywait(sems[i])) {}
    init_maps();
}

static void* retire_and_release(void* arg)
{
    role=4;
    FreeDynablock(blocks[1],1,0);
    mutex_lock(&context.mutex_dyndump);
    FlushZombieDynablocks();
    mutex_unlock(&context.mutex_dyndump);
    assert(!holds_prot && !critical_depth);
    return NULL;
}

static void* unmap_while_marking(void* arg)
{
    role=4;
    DelMmaplist(arg);
    assert(!holds_prot && !critical_depth);
    return NULL;
}

static void marker_lifetime_case(int outer_prot, int unmap)
{
    published[1]=NULL;
    force_free_race=1;
    pthread_t marker,freer;
    pthread_create(&marker,NULL,concurrent_marker,(void*)(uintptr_t)outer_prot);
    sem_wait(&checked_old); // Marker is paused after acquiring its allocation guard.
    if(unmap) {
        mmaplist_t* list=calloc(1,sizeof(*list));
        list->size=1;
        list->chunks=malloc(sizeof(*list->chunks));
        list->chunks[0]=maps[0];
        pthread_create(&freer,NULL,unmap_while_marking,list);
    } else {
        pthread_create(&freer,NULL,retire_and_release,NULL);
    }
    sem_wait(&memory_waiting); // Reclaimer reached the guard held by the marker.
    assert(pthread_mutex_trylock(&mutex_prot)==EBUSY);
    assert(present[0] && !released[1] && !blocks[1]->gone);
    sem_post(&old_freed); // Permit the deferred write before actual free/unmap.
    pthread_join(marker,NULL);
    pthread_join(freer,NULL);
    force_free_race=0;
    assert(unmap?!present[0]:released[1]==1);
    // These would access poisoned/freed memory if pointer membership was late.
    MarkDynablock(blocks[1]);
    FreeDynablock(blocks[1],1,0);
    FreeInvalidDynablock(blocks[1],1);
    assert(InvalidDynablock(blocks[1],1)==NULL);
    mutex_lock(&context.mutex_dyndump);
    RetireLostDynablocks();
    mutex_unlock(&context.mutex_dyndump);
    assert(!context.db_zombie_count);
}

static void* racing_free(void* invalid)
{
    role=5;
    if(invalid) FreeInvalidDynablock(blocks[0],1);
    else FreeDynablock(blocks[0],1,0);
    return NULL;
}

static void duplicate_queue_case(int invalid)
{
    pthread_t first,second;
    published[0]=NULL;
    if(invalid) {
        assert(InvalidDynablock(blocks[0],1)==blocks[0]);
        assert(blocks[0]->gone==1);
    }
    mutex_lock(&context.mutex_dyndump);
    if(!invalid) MarkDynablock(blocks[0]);
    pthread_create(&first,NULL,racing_free,(void*)(uintptr_t)invalid);
    sem_wait(&free_waiting); // Both old and new implementations have reached dyndump.
    if(invalid) {
        pthread_create(&second,NULL,racing_free,(void*)1);
        sem_wait(&free_waiting);
    } else {
        RetireLostDynablocks();
        assert(context.db_zombie_count==1 && size_decrements==1);
    }
    mutex_unlock(&context.mutex_dyndump);
    pthread_join(first,NULL);
    if(invalid) pthread_join(second,NULL);
    assert(context.db_zombie_count==1 && size_decrements==1);
    assert(blocks[0]->gone==2);
    FreeDynablock(blocks[0],1,0);
    FreeInvalidDynablock(blocks[0],1);
    assert(context.db_zombie_count==1 && size_decrements==1);
    mutex_lock(&context.mutex_dyndump);
    FlushZombieDynablocks();
    mutex_unlock(&context.mutex_dyndump);
    assert(released[0]==1 && release_count==1);
}

static void nested_guard_case(void)
{
    LOCK_PROT();
    assert(holds_prot && critical_depth==1);
    int first=LockDynablockMemory();
    int second=LockDynablockMemory();
    assert(first==0 && second==0 && setting_prot==2 && critical_depth==3);
    UnlockDynablockMemory(second);
    UnlockDynablockMemory(first);
    assert(holds_prot && critical_depth==1 && !setting_prot);
    assert(pthread_mutex_trylock(&mutex_prot)==EBUSY);
    UNLOCK_PROT();
    first=LockDynablockMemory();
    assert(first==1 && holds_prot && critical_depth==1);
    UnlockDynablockMemory(first);
    assert(!holds_prot && !critical_depth && !setting_prot);
}

int main(void)
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr,PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&context.mutex_dyndump,&attr);
    pthread_mutex_init(&mutex_prot,&attr);
    sem_init(&jit_locked,0,0); sem_init(&mark_locked,0,0);
    sem_init(&checked_old,0,0); sem_init(&old_freed,0,0);
    sem_init(&removal_waiting,0,0); sem_init(&memory_waiting,0,0); sem_init(&free_waiting,0,0);
    reset_case();
    nested_guard_case();
#ifndef ONLY_DUPLICATE
    original_cases();
    for(int outer=0;outer<=1;++outer) for(int unmap=0;unmap<=1;++unmap) {
        reset_case();
        marker_lifetime_case(outer,unmap);
    }
#endif
    for(int invalid=0;invalid<=1;++invalid) {
        reset_case();
        duplicate_queue_case(invalid);
    }
    for(int i=0;i<MAPS;++i) if(present[i]) free(maps[i]);
    free(context.db_orphan);
    puts("PASS: lost-block ABBA/reentry, physical-free/unmap races, duplicate retirement, nested guards, cache accounting, coalescing and shutdown");
    return 0;
}
