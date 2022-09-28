#pragma once

#include "types.h"
#include "platform.h"

COVERT_API u64					find_code_cave(void* module_base, u32 cave_size);
COVERT_API PRTL_PROCESS_MODULES get_loaded_module_list();
COVERT_API bool					is_patchguard_protected(const char* module_name);
COVERT_API bool					is_ret_op(u8 op);
COVERT_API bool					patch_code_cave_detour(u64 address, u64 hook);
COVERT_API bool					remap_page(void* address, u8* shellcode, u32 length, bool restore);
COVERT_API bool					restore_code_cave_detour(u64 address);

COVERT_API void _write_protect_off();
COVERT_API void _write_protect_on();