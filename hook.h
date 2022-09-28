#pragma once

#include "types.h"
#include "memory.h"

COVERT_API void* hook_iat_entry(void* module_base, const c_string import_name, void* hook);
COVERT_API bool  write_cc_detour(void* address, void* hook);