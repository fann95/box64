// SPDX-License-Identifier: MIT
#ifndef __PERFMAP_H__
#define __PERFMAP_H__

#include <stddef.h>
#include <stdint.h>

void writePerfMap(uintptr_t func_addr, uintptr_t code_addr, size_t code_size, const char* inst_name);

struct dynablock_s;
int jitProfileActive(void);
void writeJitProfileLoad(const struct dynablock_s* block);
void writeJitProfileUnload(const struct dynablock_s* block);

#endif // __PERFMAP_H__
