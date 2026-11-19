// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "wrappedlibs.h"
#include "wrapper32.h"
#include "bridge.h"
#include "librarian/library_private.h"
#include "x64emu.h"

static const char* libbsdName = "libbsd.so.0";
#define ALTNAME "libbsd.so"
#define LIBNAME libbsd

#include "wrappedlib_init32.h"
