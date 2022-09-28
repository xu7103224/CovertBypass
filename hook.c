#include "hook.h"

COVERT_API void* hook_iat_entry(void* module_base, const c_string import_name, void* hook) {
	if (!module_base || !import_name || !hook) return (void*)0;

	PIMAGE_DOS_HEADER dos_headers = (PIMAGE_DOS_HEADER)module_base;
	PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)module_base + dos_headers->e_lfanew);

	IMAGE_DATA_DIRECTORY imports_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)module_base + imports_directory.VirtualAddress);

	PVOID result = NULL;
	PIMAGE_IMPORT_BY_NAME function_name = NULL;

	if (!import_descriptor) return (void*)0;

	while (import_descriptor->Name != NULL) {
		PIMAGE_THUNK_DATA original_first_thunk = NULL;
		PIMAGE_THUNK_DATA first_thunk = NULL;

		original_first_thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)module_base + import_descriptor->OriginalFirstThunk);
		first_thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)module_base + import_descriptor->FirstThunk);

		while (original_first_thunk->u1.AddressOfData != NULL) {
			function_name = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)module_base + original_first_thunk->u1.AddressOfData);

			if (_stricmp(function_name->Name, import_name) == 0) {
				result = (PVOID)first_thunk->u1.Function;
				_write_protect_off();
				first_thunk->u1.Function = (ULONG64)hook;
				DbgPrint("[Covert Bypass]: IAT hook placed [%s, 0x%p] \n", import_name, hook);
				_write_protect_on();

				return result;
			}

			++original_first_thunk;
			++first_thunk;
		}

		import_descriptor++;
	}

	return NULL;
}