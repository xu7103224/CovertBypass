#include "bypass.h"

typedef bool (*Bypass_Pfn_Anticheat_Init)(PIMAGE_INFO);
typedef void (*Bypass_Pfn_Anticheat_Cleanup)();

typedef struct _Bypass_Internal_State {
	u64                          load_image_notify_routine_code_cave;
	u16*                         anticheat_driver_targets[Anticheat_Type_Count];
	Bypass_Pfn_Anticheat_Init    anticheat_init_functions[Anticheat_Type_Count];
	Bypass_Pfn_Anticheat_Cleanup anticheat_cleanup_functions[Anticheat_Type_Count];
} _Bypass_Internal_State;

static _Bypass_Internal_State _bypass_internal_state;
bool _bypass_init_image_load_callback(DRIVER_OBJECT* driver);

void _bypass_image_load_notify_callback(PUNICODE_STRING full_image_name, HANDLE proc_id, PIMAGE_INFO image_info);

static bool is_image_load_notify_routine_set = false;

COVERT_API void bypass_cleanup() {
	be_cleanup();
	eac_cleanup();
	eac_eos_cleanup();

	if(is_image_load_notify_routine_set) PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)_bypass_image_load_notify_callback);
}

COVERT_API bool bypass_initialize(DRIVER_OBJECT* driver) {
	DbgPrint("[Covert Bypass]: Initializing... \n");

	_bypass_internal_state.anticheat_driver_targets[Anticheat_Type_BE]      = L"BEDaisy.sys";
	_bypass_internal_state.anticheat_driver_targets[Anticheat_Type_EAC]     = L"EasyAntiCheat.sys";
	_bypass_internal_state.anticheat_driver_targets[Anticheat_Type_EAC_EOS] = L"EasyAntiCheat_EOS.sys";
	_bypass_internal_state.anticheat_driver_targets[Anticheat_Type_RICOCHET] = L"atvi-brynhildr.sys";
	

	_bypass_internal_state.anticheat_init_functions[Anticheat_Type_BE]      = &be_initialize;
	_bypass_internal_state.anticheat_init_functions[Anticheat_Type_EAC]     = &eac_initialize;
	_bypass_internal_state.anticheat_init_functions[Anticheat_Type_EAC_EOS] = &eac_eos_initialize;
	_bypass_internal_state.anticheat_init_functions[Anticheat_Type_RICOCHET] = &be_initialize;
	if (!_bypass_init_image_load_callback(driver)) return false;

	DbgPrint("[Covert Bypass]: Initialized successfully \n");

	return true;
}

 void safe_thread_function();

bool _bypass_init_image_load_callback(DRIVER_OBJECT* driver) {
	PRTL_PROCESS_MODULES modules = get_loaded_module_list();
	PVOID module_base{};
	PVOID module_size{};
	void* base_address = 0;
	for (ULONG i = 0; i < modules->NumberOfModules; i++) {
		PRTL_PROCESS_MODULE_INFORMATION module = &modules->Modules[i];
		if (!strstr((c_string)module->FullPathName, ".sys") || is_patchguard_protected((c_string)module->FullPathName)) continue;
		_bypass_internal_state.load_image_notify_routine_code_cave = find_code_cave(module->ImageBase, 13);
		if (_bypass_internal_state.load_image_notify_routine_code_cave != 0) {
			if (!patch_code_cave_detour(_bypass_internal_state.load_image_notify_routine_code_cave, (u64)&safe_thread_function)) return false;

			HANDLE safe_thread_handle;
			NTSTATUS safe_thread_status = PsCreateSystemThread(&safe_thread_handle, THREAD_ALL_ACCESS, 0, 0, 0, (PKSTART_ROUTINE)_bypass_internal_state.load_image_notify_routine_code_cave, 0);
			if (!NT_SUCCESS(safe_thread_status)) {
				restore_code_cave_detour(_bypass_internal_state.load_image_notify_routine_code_cave);

				continue;
			}

			break;
		}
	}

	ExFreePoolWithTag(modules, COVERT_POOL_TAG);

	return true;
}

void safe_thread_function() {
	if (!restore_code_cave_detour(_bypass_internal_state.load_image_notify_routine_code_cave)) return;
	_bypass_internal_state.load_image_notify_routine_code_cave = 0;

	PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)_bypass_image_load_notify_callback);
	is_image_load_notify_routine_set = true;
}

void _bypass_image_load_notify_callback(PUNICODE_STRING full_image_name, HANDLE proc_id, PIMAGE_INFO image_info) {
	for (u32 i = 1; i < Anticheat_Type_Count; i++) {
		if (wcsstr(full_image_name->Buffer, _bypass_internal_state.anticheat_driver_targets[i])) {
			DbgPrint("[Covert Bypass]: Detected anticheat: 0x%x (%wZ) \n", i, full_image_name);
			if (!_bypass_internal_state.anticheat_init_functions[i](image_info)) {
				DbgPrint("[Covert Bypass]: Failed to initialize bypass for anticheat: 0x%x (%wZ) \n", i, full_image_name);

				return;
			}
		}
	}
}