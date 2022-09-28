#include "platform.h"

COVERT_API void* get_module_base(const c_string module_name) {	
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

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	PVOID module_base{};
	PVOID module_size{};
	void* base_address = 0;
	for (ULONG i = 0; i < modules->NumberOfModules; i++) {
		if (_stricmp((c_string)module[i].FullPathName + module[i].OffsetToFileName, module_name) == 0) {
			base_address = module[i].ImageBase;

			break;
		}
	}

	ExFreePoolWithTag(modules, COVERT_POOL_TAG);

	return base_address;
}