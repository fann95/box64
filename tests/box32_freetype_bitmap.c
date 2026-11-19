// SPDX-License-Identifier: MIT
#include <assert.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "debug.h"
#include "emu/x64emu_private.h"
#include "wrapper32.h"
#include "converter32.h"

// Select the registered wrappers, including their structure direction.
#define GO(name, signature) static wrapper_t const wrap_##name = signature##_32;
#define GOM(name, signature) static wrapper_t const wrap_##name = signature##_32;
#define GO2(name, signature, target)
#define DATA(name, size)
#include "wrapped32/wrappedfreetype_private.h"
#undef DATA
#undef GO2
#undef GOM
#undef GO

#include "wrapped32/wrappedfreetype.c"

box64env_t box64env;

void PrintfFtrace(int prefix, const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

void box64_abort(void)
{
    abort();
}

void* customMalloc(size_t size) { return malloc(size); }
void* customCalloc(size_t count, size_t size) { return calloc(count, size); }
void* customRealloc(void* pointer, size_t size) { return realloc(pointer, size); }
void customFree(void* pointer) { free(pointer); }

void* GetNativeFnc(uintptr_t function)
{
    abort(); // The pathname-based FT_Open_Face test does not use callbacks.
}

uint64_t RunFunctionFmt(uintptr_t function, const char* format, ...)
{
    abort();
}

typedef struct ft_memory_s ft_memory_t;
struct ft_memory_s {
    void* user;
    void* (*alloc)(ft_memory_t*, long);
    void (*free)(ft_memory_t*, void*);
    void* (*realloc)(ft_memory_t*, long, long, void*);
};

typedef struct {
    uint32_t rows, width;
    int32_t pitch;
    uint32_t buffer;
    uint16_t num_grays;
    uint8_t pixel_mode, palette_mode;
    uint32_t palette;
} bitmap32_t;

typedef struct {
    uint32_t before;
    bitmap32_t bitmap;
    uint32_t after;
} guarded_bitmap_t;

static unsigned char* arena;
static size_t used;
enum { ARENA_SIZE = 8 * 1024 * 1024 };
static struct { void* pointer; int live; } allocations[2048];
static unsigned allocation_count;

static void* allocate(ft_memory_t* memory, long bytes)
{
    assert(bytes > 0 && used + (size_t)bytes < ARENA_SIZE);
    assert(allocation_count < sizeof(allocations) / sizeof(allocations[0]));
    void* result = arena + used;
    used += ((size_t)bytes + 15) & ~(size_t)15;
    allocations[allocation_count].pointer = result;
    allocations[allocation_count++].live = 1;
    return result;
}

static int is_live(void* pointer)
{
    for (unsigned i = 0; i < allocation_count; ++i)
        if (allocations[i].pointer == pointer)
            return allocations[i].live;
    return 0;
}

static void release(ft_memory_t* memory, void* pointer)
{
    if (!pointer) return;
    for (unsigned i = 0; i < allocation_count; ++i) {
        if (allocations[i].pointer == pointer) {
            assert(allocations[i].live && "double free");
            allocations[i].live = 0;
            return;
        }
    }
    assert(0 && "foreign allocation");
}

static void* reallocate(ft_memory_t* memory, long old_size, long size, void* pointer)
{
    if (!size) { release(memory, pointer); return NULL; }
    void* result = allocate(memory, size);
    if (pointer) {
        assert(is_live(pointer));
        memcpy(result, pointer, old_size < size ? old_size : size);
        release(memory, pointer);
    }
    return result;
}

static int (*native_embolden)(void*, struct_uuipWCCp_t*, long, long);
static struct_uuipWCCp_t observed;

static int observe_embolden(void* library, struct_uuipWCCp_t* bitmap, long x, long y)
{
    int result = native_embolden(library, bitmap, x, y);
    observed = *bitmap;
    return result;
}

static int test_outlines(void* handle, void* library, ft_memory_t* memory)
{
    int failures = 0;
    my->FT_Outline_Get_CBox = dlsym(handle, "FT_Outline_Get_CBox");
    my->FT_Outline_Translate = dlsym(handle, "FT_Outline_Translate");
    my->FT_New_Face = dlsym(handle, "FT_New_Face");
    my->FT_Set_Pixel_Sizes = dlsym(handle, "FT_Set_Pixel_Sizes");
    my->FT_Get_Char_Index = dlsym(handle, "FT_Get_Char_Index");
    my->FT_Load_Glyph = dlsym(handle, "FT_Load_Glyph");
    my->FT_Render_Glyph = dlsym(handle, "FT_Render_Glyph");
    my->FT_Done_Face = dlsym(handle, "FT_Done_Face");
    void (*add_modules)(void*) = dlsym(handle, "FT_Add_Default_Modules");
    assert(add_modules && my->FT_Outline_Get_CBox && my->FT_Outline_Translate);

    const FT_Vector_32_t original[] = {{64, 128}, {640, 128}, {640, 768}, {64, 768}};
    FT_Vector_32_t* points = allocate(memory, 4 * sizeof(FT_Vector_t));
    memcpy(points, original, sizeof(original));
    FT_Outline_32_t outline = {1, 4, to_ptrv(points), 0, 0, 0};
    FT_BBox_32_t box;
    my32_FT_Outline_Get_CBox(NULL, &outline, &box);
    if (memcmp(points, original, sizeof(original)) ||
        box.xMin != 64 || box.yMin != 128 || box.xMax != 640 || box.yMax != 768) {
        fprintf(stderr, "FAIL: FT_Outline_Get_CBox changed the contour or its bounds\n");
        ++failures;
    }

    add_modules(library);
    ptr_t face_pointer = 0;
    assert(!my32_FT_New_Face(NULL, library, "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 0, &face_pointer));
    FT_FaceRec_32_t* face = from_ptrv(face_pointer);
    assert(!my32_FT_Set_Pixel_Sizes(NULL, face, 0, 16));
    unsigned index = my32_FT_Get_Char_Index(NULL, face, 'A');
    assert(index && !my32_FT_Load_Glyph(NULL, face, index, 3 << 16));
    FT_GlyphSlotRec_32_t* glyph = from_ptrv(face->glyph);
    // CEF queries bounds, translates the contour, then requests an LCD bitmap.
    my32_FT_Outline_Get_CBox(NULL, &glyph->outline, &box);
    my32_FT_Outline_Translate(NULL, &glyph->outline, -(box.xMin & -64), -(box.yMin & -64));
    int error = my32_FT_Render_Glyph(NULL, glyph, 3);
    if (error || !glyph->bitmap.buffer || !glyph->bitmap.rows || !glyph->bitmap.width) {
        fprintf(stderr, "FAIL: CEF-style outline/render sequence: error=%d buffer=0x%x size=%ux%u\n",
                error, glyph->bitmap.buffer, glyph->bitmap.width, glyph->bitmap.rows);
        ++failures;
    } else {
        printf("PASS: CEF-style outline/render sequence produces a %ux%u LCD bitmap\n",
               glyph->bitmap.width, glyph->bitmap.rows);
    }
    assert(!my32_FT_Done_Face(NULL, face));
    return failures;
}

static int done_guest_library(void* library, ft_memory_t* memory)
{
    x64emu_t emu = {0};
    uint32_t* stack = allocate(memory, 8);
    stack[1] = to_ptrv(library);
    emu.regs[4].dword[0] = to_ptrv(stack);
    wrap_FT_Done_FreeType(&emu, (uintptr_t)my32_FT_Done_FreeType);
    return emu.regs[0].sdword[0];
}

static void test_library_teardown(void* handle, ft_memory_t* memory)
{
    int (*new_library)(ft_memory_t*, void**) = dlsym(handle, "FT_New_Library");
    void (*add_modules)(void*) = dlsym(handle, "FT_Add_Default_Modules");
    // FT_Done_FreeType uses FT_Done_Library to destroy faces. With our custom
    // allocator, use that same path without freeing the caller-owned memory record.
    my->FT_Done_FreeType = dlsym(handle, "FT_Done_Library");
    my->FT_New_Memory_Face = dlsym(handle, "FT_New_Memory_Face");
    my->FT_Open_Face = dlsym(handle, "FT_Open_Face");
    my->FT_Reference_Face = dlsym(handle, "FT_Reference_Face");
    assert(new_library && add_modules && my->FT_Done_FreeType);

    const char* font_path = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf";
    char* path = allocate(memory, strlen(font_path) + 1);
    strcpy(path, font_path);
    FILE* font = fopen(path, "rb");
    assert(font && !fseek(font, 0, SEEK_END));
    long length = ftell(font);
    assert(length > 0 && !fseek(font, 0, SEEK_SET));
    void* data = allocate(memory, length);
    assert(fread(data, 1, length, font) == (size_t)length);
    fclose(font);

    void* libraries[2] = {0};
    for(int i = 0; i < 2; ++i) {
        assert(!new_library(memory, &libraries[i]));
        add_modules(libraries[i]);
    }
    ptr_t faces[4] = {0};
    assert(!my32_FT_New_Face(NULL, libraries[0], path, 0, &faces[0]));
    assert(!my32_FT_New_Memory_Face(NULL, libraries[0], data, length, 0, &faces[1]));
    FT_Open_Args_32_t args = {.flags = 4, .pathname = to_ptrv(path)};
    assert(!my32_FT_Open_Face(NULL, libraries[0], &args, 0, &faces[2]));
    assert(!my32_FT_New_Face(NULL, libraries[1], path, 0, &faces[3]));

    // Releasing one reference must leave a usable guest-layout face. The last
    // release must remove it from the set visited at library teardown.
    void* referenced = from_ptrv(faces[0]);
    assert(!my32_FT_Reference_Face(NULL, referenced));
    assert(!my32_FT_Reference_Face(NULL, referenced));
    for(int i = 0; i < 2; ++i) {
        assert(!my32_FT_Done_Face(NULL, referenced));
        assert(is_live(referenced));
        assert(!my32_FT_Set_Pixel_Sizes(NULL, referenced, 0, 16));
        assert(my32_FT_Get_Char_Index(NULL, referenced, 'A'));
    }
    assert(!my32_FT_Done_Face(NULL, referenced));
    assert(!is_live(referenced));
    assert(!my32_FT_Reference_Face(NULL, from_ptrv(faces[1])));

    FT_FaceRec_32_t untouched = *(FT_FaceRec_32_t*)from_ptrv(faces[3]);
    assert(done_guest_library(NULL, memory));
    assert(!done_guest_library(libraries[0], memory));
    assert(!is_live(libraries[0]));
    assert(!is_live(from_ptrv(faces[1])) && !is_live(from_ptrv(faces[2])));
    assert(is_live(libraries[1]) && is_live(from_ptrv(faces[3])));
    assert(!memcmp(&untouched, from_ptrv(faces[3]), sizeof(untouched)));
    assert(!my32_FT_Set_Pixel_Sizes(NULL, from_ptrv(faces[3]), 0, 20));
    assert(my32_FT_Get_Char_Index(NULL, from_ptrv(faces[3]), 'B'));
    assert(!done_guest_library(libraries[1], memory));
    assert(!is_live(libraries[1]) && !is_live(from_ptrv(faces[3])));
    assert(is_live(data));
    release(memory, data);
    release(memory, path);

    void* empty_library = NULL;
    assert(!new_library(memory, &empty_library));
    assert(!done_guest_library(empty_library, memory));
    puts("PASS: library teardown releases live faces, preserves other libraries and handles face references");
}

int main(void)
{
    _Static_assert(sizeof(bitmap32_t) == 24, "i386 FT_Bitmap size");
    arena = mmap((void*)0x60000000, ARENA_SIZE, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    assert(arena != MAP_FAILED);
    void* handle = dlopen("libfreetype.so.6", RTLD_NOW | RTLD_LOCAL);
    assert(handle);
    int (*new_library)(ft_memory_t*, void**) = dlsym(handle, "FT_New_Library");
    int (*done_library)(void*) = dlsym(handle, "FT_Done_Library");
    int (*done_bitmap)(void*, struct_uuipWCCp_t*) = dlsym(handle, "FT_Bitmap_Done");
    native_embolden = dlsym(handle, "FT_Bitmap_Embolden");
    assert(new_library && done_library && done_bitmap && native_embolden);

    ft_memory_t memory = {NULL, allocate, release, reallocate};
    void* library = NULL;
    assert(!new_library(&memory, &library));
    x64emu_t emu = {0};
    uint32_t* stack = allocate(&memory, 32);
    emu.regs[4].dword[0] = to_ptrv(stack);
    guarded_bitmap_t* guarded = allocate(&memory, sizeof(*guarded));
    int failures = 0;

    for (int sign = 1; sign >= -1; sign -= 2) {
        unsigned char* original = allocate(&memory, 4);
        memcpy(original, "\x10\x20\x40\x80", 4);
        *guarded = (guarded_bitmap_t){
            0x12345678, {2, 2, 2 * sign, to_ptrv(original), 256, 2, 0, 0}, 0x87654321
        };
        stack[1] = to_ptrv(library);
        stack[2] = to_ptrv(&guarded->bitmap);
        stack[3] = stack[4] = 64;
        wrap_FT_Bitmap_Embolden(&emu, (uintptr_t)observe_embolden);
        assert(!emu.regs[0].dword[0]);
        assert(!is_live(original) && is_live(observed.p3));
        assert(observed.u0 == 3 && observed.u1 == 3 && observed.i2 == 3 * sign);
        bitmap32_t expected;
        // Compare the guest result with the actual FreeType output.
        guarded_bitmap_t* reference = allocate(&memory, sizeof(*reference));
        to_struct_uuipWCCp(to_ptrv(&reference->bitmap), &observed);
        expected = reference->bitmap;
        if (memcmp(&guarded->bitmap, &expected, sizeof(expected))) {
            fprintf(stderr, "FAIL: FT_Bitmap_Embolden lost new buffer/dimensions (pitch sign %d)\n", sign);
            ++failures;
        }
        assert(guarded->before == 0x12345678 && guarded->after == 0x87654321);

        // Restore the known native result so teardown can be tested independently.
        guarded->bitmap = expected;
        wrap_FT_Bitmap_Done(&emu, (uintptr_t)done_bitmap);
        assert(!emu.regs[0].dword[0] && !is_live(observed.p3));
        bitmap32_t empty = {0};
        if (memcmp(&guarded->bitmap, &empty, sizeof(empty))) {
            fprintf(stderr, "FAIL: FT_Bitmap_Done left a freed buffer in the guest bitmap\n");
            ++failures;
        } else {
            wrap_FT_Bitmap_Done(&emu, (uintptr_t)done_bitmap);
            assert(!emu.regs[0].dword[0]);
        }
        assert(guarded->before == 0x12345678 && guarded->after == 0x87654321);
    }
    assert(!done_library(library));
    // Face conversion exposes the allocator pointer to the 32-bit guest.
    ft_memory_t* low_memory = allocate(&memory, sizeof(*low_memory));
    *low_memory = memory;
    assert(!new_library(low_memory, &library));
    failures += test_outlines(handle, library, low_memory);
    assert(!done_library(library));
    test_library_teardown(handle, low_memory);
    dlclose(handle);
    munmap(arena, ARENA_SIZE);
    if (!failures)
        puts("PASS: FreeType wrappers preserve contour coordinates, bitmap buffers and teardown");
    return failures ? 1 : 0;
}
