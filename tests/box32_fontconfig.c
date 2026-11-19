// SPDX-License-Identifier: MIT
#include <assert.h>
#include <stdarg.h>

#include "wrapped32/wrappedfontconfig.c"

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

typedef struct {
    uint32_t before;
    FcValue_32_t value;
    uint32_t after;
} guarded_value_t;

static guarded_value_t output;

static void reset_output(void)
{
    memset(&output, 0xa5, sizeof(output));
}

static void check_guards(void)
{
    assert(output.before == UINT32_C(0xa5a5a5a5));
    assert(output.after == UINT32_C(0xa5a5a5a5));
}

static uint32_t pointer_value(void* pattern, void* object, int id, void* value)
{
    FcValue_t* native = value;
    native->type = id;
    native->u.c = (void*)(uintptr_t)UINT32_C(0xf1234560);
    return 0;
}

int main(void)
{
    _Static_assert(sizeof(FcValue_32_t) == 12, "i386 FcValue size");
    void* handle = dlopen("libfontconfig.so.1", RTLD_NOW | RTLD_LOCAL);
    assert(handle);
    void* (*create)(void) = dlsym(handle, "FcPatternCreate");
    void (*destroy)(void*) = dlsym(handle, "FcPatternDestroy");
    int (*add_int)(void*, const char*, int) = dlsym(handle, "FcPatternAddInteger");
    int (*add_double)(void*, const char*, double) = dlsym(handle, "FcPatternAddDouble");
    int (*add_bool)(void*, const char*, int) = dlsym(handle, "FcPatternAddBool");
    my->FcPatternGet = dlsym(handle, "FcPatternGet");
    assert(create && destroy && add_int && add_double && add_bool && my->FcPatternGet);
    void* pattern = create();
    assert(pattern);
    assert(add_int(pattern, "rgba", 1));
    assert(add_double(pattern, "size", 13.25));
    assert(add_bool(pattern, "antialias", 1));

    reset_output();
    assert(my32_FcPatternGet(NULL, pattern, "rgba", 0, &output.value) == 0);
    check_guards();
    assert(output.value.type == 1 && output.value.u.i == 1);

    reset_output();
    assert(my32_FcPatternGet(NULL, pattern, "size", 0, &output.value) == 0);
    check_guards();
    assert(output.value.type == 2 && output.value.u.d == 13.25);

    reset_output();
    assert(my32_FcPatternGet(NULL, pattern, "antialias", 0, &output.value) == 0);
    check_guards();
    assert(output.value.type == 4 && output.value.u.b == 1);

    reset_output();
    guarded_value_t unchanged = output;
    assert(my32_FcPatternGet(NULL, pattern, "missing-property", 0, &output.value) != 0);
    assert(!memcmp(&output, &unchanged, sizeof(output)));

    // Exercise all pointer variants without depending on the host heap address.
    my->FcPatternGet = pointer_value;
    const int types[] = {3, 5, 6, 7, 8, 9};
    for (unsigned i = 0; i < sizeof(types) / sizeof(types[0]); ++i) {
        reset_output();
        assert(my32_FcPatternGet(NULL, NULL, NULL, types[i], &output.value) == 0);
        check_guards();
        assert(output.value.type == types[i]);
        assert(output.value.u.c == UINT32_C(0xf1234560));
    }
    destroy(pattern);
    dlclose(handle);
    puts("PASS: FcPatternGet preserves i386 values, pointers and buffer boundaries");
    return 0;
}
