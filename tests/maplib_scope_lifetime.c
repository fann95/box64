// SPDX-License-Identifier: MIT
// Run the production local-scope ownership and promotion functions under ASan.
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct x64emu_s { int unused; } x64emu_t;
typedef struct library_s library_t;
typedef struct lib_s {
    library_t **libraries;
    int libsz, libcap;
    library_t *owner;
} lib_t;
struct library_s { int type; lib_t *maplib; int maplib_ref; };
enum { LIB_UNNKNOW, LIB_EMULATED };
static int box64_is32bits, freed_scopes;
static struct { lib_t *maplib, *local_maplib; } context, *my_context = &context;
#define box_realloc realloc

static void FreeLibrarian(lib_t **scope, x64emu_t *emu)
{
    (void)emu;
    assert(scope && *scope);
    free((*scope)->libraries);
    free(*scope);
    *scope = NULL;
    ++freed_scopes;
}

#include "maplib_scope_functions.inc"

static lib_t *scope_for(library_t *libraries, int count)
{
    lib_t *scope = calloc(1, sizeof(*scope));
    assert(scope);
    for (int i = 0; i < count; ++i) {
        libraries[i] = (library_t){LIB_EMULATED, scope, i != 0};
        MapLibAddLib(scope, &libraries[i]);
    }
    // Existing scopes do not initialize owner; ownership comes from maplib_ref.
    assert(!scope->owner);
    return scope;
}

static void test_unload_order(void)
{
    library_t libs[3];
    lib_t *scope = scope_for(libs, 3);
    int before = freed_scopes;
    DetachLibraryMaplib(&libs[0], NULL, 1);
    assert(!libs[0].maplib && !libs[1].maplib_ref);
    assert(scope->libsz == 2 && scope->libraries[0] == &libs[1]);
    assert(freed_scopes == before);
    // This is the scope still needed by B's deferred TLS destructor/finalizer.
    assert(libraryInMapLib(libs[1].maplib, &libs[2]));
    DetachLibraryMaplib(&libs[1], NULL, 1);
    assert(!libs[2].maplib_ref && scope->libsz == 1);
    assert(freed_scopes == before);
    DetachLibraryMaplib(&libs[2], NULL, 1);
    assert(freed_scopes == before + 1);
    DetachLibraryMaplib(&libs[2], NULL, 1);
    assert(freed_scopes == before + 1);
}

static void test_borrower_and_foreign_member(void)
{
    library_t libs[3], foreign = {LIB_EMULATED, NULL, 0};
    lib_t *scope = scope_for(libs, 3);
    int before = freed_scopes;
    MapLibAddLib(scope, &foreign);
    DetachLibraryMaplib(&libs[1], NULL, 1);
    assert(scope->libsz == 3 && !libraryInMapLib(scope, &libs[1]));
    assert(freed_scopes == before);
    DetachLibraryMaplib(&libs[0], NULL, 1);
    assert(!libs[2].maplib_ref);
    DetachLibraryMaplib(&libs[2], NULL, 1);
    assert(freed_scopes == before + 1); // Foreign membership does not own this scope.
}

static void test_promotion(void)
{
    library_t libs[3];
    lib_t *scope = scope_for(libs, 3);
    int before = freed_scopes;
    context.maplib = calloc(1, sizeof(lib_t));
    context.local_maplib = calloc(1, sizeof(lib_t));
    assert(context.maplib && context.local_maplib);
    for (int i = 0; i < 3; ++i) MapLibAddLib(context.local_maplib, &libs[i]);
    promoteLocalLibGlobal(&libs[0]);
    assert(!libs[0].maplib && !libs[1].maplib_ref);
    assert(context.maplib->libsz == 3 && !context.local_maplib->libsz);
    // A is still loaded and remains available for B's local symbol searches.
    assert(libraryInMapLib(scope, &libs[0]));
    assert(freed_scopes == before);
    promoteLocalLibGlobal(&libs[1]);
    assert(!libs[1].maplib && !libs[2].maplib_ref);
    assert(freed_scopes == before);
    promoteLocalLibGlobal(&libs[2]);
    assert(!libs[2].maplib && freed_scopes == before + 1);
    FreeLibrarian(&context.maplib, NULL);
    FreeLibrarian(&context.local_maplib, NULL);
}

static void test_borrower_promotion(void)
{
    library_t libs[2];
    lib_t *scope = scope_for(libs, 2);
    int before = freed_scopes;
    context.maplib = calloc(1, sizeof(lib_t));
    context.local_maplib = calloc(1, sizeof(lib_t));
    assert(context.maplib && context.local_maplib);
    for (int i = 0; i < 2; ++i) MapLibAddLib(context.local_maplib, &libs[i]);
    promoteLocalLibGlobal(&libs[1]);
    assert(!libs[1].maplib && !libs[0].maplib_ref);
    assert(freed_scopes == before && libraryInMapLib(scope, &libs[1]));
    assert(context.maplib->libsz == 1 && context.local_maplib->libsz == 1);
    // With no borrowers left, promotion of the owner frees the obsolete scope.
    scope->owner = &libs[0];
    promoteLocalLibGlobal(&libs[0]);
    assert(!libs[0].maplib && freed_scopes == before + 1);
    assert(context.maplib->libsz == 2 && !context.local_maplib->libsz);
    FreeLibrarian(&context.maplib, NULL);
    FreeLibrarian(&context.local_maplib, NULL);
}

static void test_32_bit_preserved(void)
{
    library_t libs[2];
    lib_t *scope = scope_for(libs, 2);
    int before = freed_scopes;
    box64_is32bits = 1;
    DetachLibraryMaplib(&libs[1], NULL, 1);
    assert(scope->libsz == 2 && freed_scopes == before); // Original borrower behavior.
    DetachLibraryMaplib(&libs[0], NULL, 1);
    assert(freed_scopes == before + 1);
    box64_is32bits = 0;
}

int main(void)
{
    test_unload_order();
    test_borrower_and_foreign_member();
    test_promotion();
    test_borrower_promotion();
    test_32_bit_preserved();
    puts("PASS: local scope survives owner/dependency unload and promotion, freed once by last user");
    return 0;
}
