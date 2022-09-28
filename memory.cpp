#include "memory.h"

COVERT_API u64 find_code_cave(void* module_base, u32 cave_size) {
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module_base;
	IMAGE_NT_HEADERS* nt_header  = (IMAGE_NT_HEADERS*)((u8*)module_base + dos_header->e_lfanew);

	u64 start = 0, size = 0;

	u64 header_offset = (u64)IMAGE_FIRST_SECTION(nt_header);
	for (i32 x = 0; x < nt_header->FileHeader.NumberOfSections; ++x) {
		IMAGE_SECTION_HEADER* header = (IMAGE_SECTION_HEADER*)header_offset;

		if (strcmp((CHAR*)header->Name, ".text") == 0) {
			start = (u64)module_base + header->PointerToRawData;
			size = header->SizeOfRawData;
			break;
		}

		header_offset += sizeof(IMAGE_SECTION_HEADER);
	}

	u64 match = 0;
	i32 cur_length = 0;
	BOOLEAN ret = FALSE;

	for (u64 cur = start; cur < start + size; ++cur) {
		if (!ret && is_ret_op(*(u8*)cur)) ret = true;
		else if (ret && *(u8*)cur == 0xCC) {
			if (!match) match = cur;
			if (cur_length++ == cave_size) return match;
		} else {
			match = cur_length = 0;
			ret = false;
		}
	}

	return 0;
}

COVERT_API PRTL_PROCESS_MODULES get_loaded_module_list() {
	ULONG bytes{};

	NTSTATUS system_info_status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);
	if (!bytes) return false;

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, COVERT_POOL_TAG);
	if (!modules) return false;

	system_info_status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);
	if (!NT_SUCCESS(system_info_status)) {
		ExFreePoolWithTag(modules, COVERT_POOL_TAG);

		return false;
	}

	return modules;
}

COVERT_API bool is_patchguard_protected(const char* module_name) {
	static const i32 count = 8;
	static const c_string images[] = { "win32kbase.sys", "tm.sys", "clfs.sys", "msrcp.sys", "ndis.sys", "ntfs.sys", "tcpip.sys", "fltmgr.sys" };

	for (i32 i = 0; i < count; i++) {
		if (strstr(images[i], module_name)) return true;
	}

	return false;
}

COVERT_API bool is_ret_op(u8 op) {
	return (op == 0xC2 || op == 0xC3 || op == 0xCA || op == 0xCB);
}

COVERT_API bool patch_code_cave_detour(u64 address, u64 hook) {
	u8 shellcode[16] = {
		0x50,															/* push rax */
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		/* mov rax, hook */
		0x48, 0x87, 0x04, 0x24,											/* xchg QWORD PTR[rsp], rax */
		0xC3                                                            /* retn */
	};

	*(u64*)(shellcode + 3) = hook;

	return remap_page((void*)address, shellcode, 16, false);
}

COVERT_API bool remap_page(void* address, u8* shellcode, u32 length, bool restore) {
	MDL* mdl = IoAllocateMdl(address, length, false, false, 0);
	if (!mdl) return false;

	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

	void* map_address = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, 0, false, NormalPagePriority);
	if (!map_address) {
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);

		return false;
	}

	NTSTATUS protect_status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
	if (protect_status) {
		MmUnmapLockedPages(map_address, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);

		return false;
	}

	RtlCopyMemory(map_address, shellcode, length);

	if (restore) {
		protect_status = MmProtectMdlSystemAddress(mdl, PAGE_READONLY);
		if (protect_status) {
			MmUnmapLockedPages(map_address, mdl);
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);

			return false;
		}
	}

	MmUnmapLockedPages(map_address, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	return true;
}

COVERT_API bool restore_code_cave_detour(u64 address) {
	u8 shellcode[16] = {
		0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
	};

	return remap_page((void*)address, shellcode, 16, true);
}

COVERT_API void _write_protect_off() {
	auto cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
}

COVERT_API void _write_protect_on() {
	auto cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
}