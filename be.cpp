#include "be.h"

void*	  _be_flt_get_routine_address(c_string routine_name);
void*	  _be_mm_get_system_routine_address(PUNICODE_STRING system_routine_name);
NTSTATUS  _be_ob_register_callbacks(POB_CALLBACK_REGISTRATION callback_registration, PVOID* registration_handle);
NTSTATUS _be_ob_open_object_by_pointer(PVOID Object, ULONG HandleAttributes, PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PHANDLE Handle);
NTSTATUS  _be_ps_create_system_thread(PHANDLE thread_handle, ULONG access, POBJECT_ATTRIBUTES obj_attr, HANDLE proc_handle, PCLIENT_ID client_id, PKSTART_ROUTINE start_routine, PVOID start_context);
NTSTATUS  _be_ps_set_create_process_notify_routine_ex(PCREATE_PROCESS_NOTIFY_ROUTINE_EX notify_routine, BOOLEAN remove);
NTSTATUS  _be_ps_set_create_thread_notify_routine(PCREATE_THREAD_NOTIFY_ROUTINE notify_routine);
NTSTATUS  _be_ps_set_load_image_notify_routine(PLOAD_IMAGE_NOTIFY_ROUTINE notify_routine);
NTSTATUS  _be_zw_query_information_thread(HANDLE thread_handle, THREADINFOCLASS info_class, PVOID info, ULONG info_length, PULONG return_length);
NTSTATUS  _be_zw_query_system_information(SYSTEM_INFORMATION_CLASS info_class, PVOID info, ULONG info_length, PULONG return_length);
NTSTATUS _be_rtl_get_version(RTL_OSVERSIONINFOW VersionInformation);
BOOLEAN _be_ke_insert_queue_apc_hook(PRKAPC Apc, PVOID SystemArgument1, PVOID SystemArgument2, KPRIORITY Increment);
NTSTATUS _be_ps_lookup_thread_by_threadid_hook(HANDLE ThreadId, PETHREAD* Thread);
NTSTATUS _be_ps_remove_load_image_notify_routine_hook(PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine);
NTSTATUS _ps_remove_create_thread_notify_routine_hook(PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine);
NTSTATUS _be_ps_set_load_image_notify_routine_2(PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine);

static u64 _be_pre_ob_callback_cave = 0;
static POB_PRE_OPERATION_CALLBACK _be_original_ob_callback = 0;
static u64 _be_load_image_notify_routine_code_cave     = 0;
static u64 _be_create_process_notify_routine_code_cave = 0;
static u64 _be_create_thread_notify_routine_code_cave  = 0;

COVERT_API void be_cleanup() {
	if (_be_load_image_notify_routine_code_cave != 0) {
		PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)_be_load_image_notify_routine_code_cave);
		restore_code_cave_detour(_be_load_image_notify_routine_code_cave);
	}

	if (_be_create_process_notify_routine_code_cave != 0) {
		// This occurs courtesy of battleye in the hooks section below
		//PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)_be_create_process_notify_routine_code_cave, true);
		restore_code_cave_detour(_be_create_process_notify_routine_code_cave);
	}

	if (_be_create_thread_notify_routine_code_cave != 0) {
		PsRemoveCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)_be_create_thread_notify_routine_code_cave);
		restore_code_cave_detour(_be_create_thread_notify_routine_code_cave);
	}
}

COVERT_API bool be_initialize(PIMAGE_INFO image_info) {
	DbgPrint("[Covert Bypass]: BE Bypass Initializing...");

	if (!hook_iat_entry(image_info->ImageBase, "FltGetRoutineAddress", &_be_flt_get_routine_address))		     return false;
	if (!hook_iat_entry(image_info->ImageBase, "MmGetSystemRoutineAddress", &_be_mm_get_system_routine_address)) return false;

	return true;
}



void* _be_mm_get_system_routine_address(PUNICODE_STRING system_routine_name) {
	//DbgPrint("[Covert Bypass]: BE called MmGetSystemRoutineAddress(%wZ) from 0x%p \n", system_routine_name, _ReturnAddress());
	
	
	if (wcsstr(system_routine_name->Buffer, L"KeInsertQueueApc_hook"))				return &_be_ke_insert_queue_apc_hook;
	if (wcsstr(system_routine_name->Buffer, L"RtlGetVersion"))						return &_be_rtl_get_version;
	if (wcsstr(system_routine_name->Buffer, L"ObRegisterCallbacks"))				return &_be_ob_register_callbacks;
	if (wcsstr(system_routine_name->Buffer, L"ObOpenObjectByPointer"))				return &_be_ob_open_object_by_pointer;
	if (wcsstr(system_routine_name->Buffer, L"PsCreateSystemThread"))				return &_be_ps_create_system_thread;
	if (wcsstr(system_routine_name->Buffer, L"PsSetLoadImageNotifyRoutine"))		return &_be_ps_set_load_image_notify_routine;
	//if (wcsstr(system_routine_name->Buffer, L"PsSetCreateProcessNotifyRoutineEx"))	return &_be_ps_set_create_process_notify_routine_ex;
	//if (wcsstr(system_routine_name->Buffer, L"PsRemoveLoadImageNotifyRoutine"))		return &_be_ps_remove_load_image_notify_routine_hook;
	//if (wcsstr(system_routine_name->Buffer, L"PsSetCreateThreadNotifyRoutine"))		return &_be_ps_set_create_thread_notify_routine;
	//if (wcsstr(system_routine_name->Buffer, L"PsRemoveCreateThreadNotifyRoutine"))	return &_ps_remove_create_thread_notify_routine_hook;
	if (wcsstr(system_routine_name->Buffer, L"PsLookupThreadByThreadId"))			return &_be_ps_lookup_thread_by_threadid_hook;
	if (wcsstr(system_routine_name->Buffer, L"ZwQueryInformationThread"))			return &_be_zw_query_information_thread;
	if (wcsstr(system_routine_name->Buffer, L"ZwQuerySystemInformation"))			return &_be_zw_query_system_information;



	return MmGetSystemRoutineAddress(system_routine_name);
}




NTSTATUS _be_ps_remove_load_image_notify_routine_hook(PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine) {
	UNREFERENCED_PARAMETER(NotifyRoutine);
	DbgPrint("[Covert Bypass]: [PsRemoveLoadImageNotifyRoutine] PsRemoveLoadImageNotifyRoutine hooked\r\n");
	
	return PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)_be_load_image_notify_routine_code_cave);
}

NTSTATUS _ps_remove_create_thread_notify_routine_hook(PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine) {
	UNREFERENCED_PARAMETER(NotifyRoutine);
	DbgPrint("[Covert Bypass]: [PsRemoveCreateThreadNotifyRoutine] PsRemoveCreateThreadNotifyRoutine hooked\r\n");
	return PsRemoveCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)_be_create_thread_notify_routine_code_cave);
}


BOOLEAN _be_ke_insert_queue_apc_hook(PRKAPC Apc, PVOID SystemArgument1, PVOID SystemArgument2, KPRIORITY Increment) {
	UNREFERENCED_PARAMETER(Apc);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	UNREFERENCED_PARAMETER(Increment);
	DbgPrint("[Covert Bypass]: [KeInsertQueueApc] APC insertion blocked\r\n");
	return false;
}


NTSTATUS _be_rtl_get_version(RTL_OSVERSIONINFOW VersionInformation) {
	UNREFERENCED_PARAMETER(VersionInformation);
	DbgPrint("[Covert Bypass]: [RtlGetVersion] Blocked handle enumeration\r\n");
	return -1;
}

PVOID gh_FltGetRequestorProcess(PFLT_CALLBACK_DATA CallbackData)
{
	DbgPrint("[Covert Bypass]:  - FltGetRequestorProcess Spoofed\r\n");
	return nullptr;
}


void* _be_flt_get_routine_address(c_string FltMgrRoutineName) {
	//DbgPrint("[Covert Bypass]: BE called FltGetRoutineAddress(%s) from 0x%p \n", routine_name, _ReturnAddress());
	DbgPrint("[Covert Bypass]:  - Filtering Manager  %s\r\n", FltMgrRoutineName);


	if (_stricmp(FltMgrRoutineName, "FltGetRequestorProcess"))
	{
		DbgPrint("[Covert Bypass]: Hooking FltGetRequestorProcess\r\n");
		return &gh_FltGetRequestorProcess;
	}

	return FltGetRoutineAddress(FltMgrRoutineName);
}

NTSTATUS _be_ob_open_object_by_pointer(PVOID Object, ULONG HandleAttributes, PACCESS_STATE PassedAccessState,
ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PHANDLE Handle
) {
	//DbgPrint("[Covert Bypass]: ObOpenObjectByPointer was called! \n");

	return ObOpenObjectByPointer(Object, HandleAttributes,PassedAccessState,
		DesiredAccess, ObjectType, AccessMode, Handle);
}



OB_PREOP_CALLBACK_STATUS pre_operation_callback_hook(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
	auto result = _be_original_ob_callback(RegistrationContext, OperationInformation);

	OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;

	return result;
}


NTSTATUS _be_ob_register_callbacks(POB_CALLBACK_REGISTRATION callback_registration, PVOID* registration_handle) {
	DbgPrint("[Covert Bypass]: BE called ObRegisterCallbacks from 0x%p \r\n", _ReturnAddress());

	_be_original_ob_callback = callback_registration->OperationRegistration->PreOperation;
	PRTL_PROCESS_MODULES modules = get_loaded_module_list();
	PVOID module_base{};
	PVOID module_size{};
	void* base_address = 0;
	for (ULONG i = 0; i < modules->NumberOfModules; i++) {
		PRTL_PROCESS_MODULE_INFORMATION module = &modules->Modules[i];
		if (!strstr((c_string)module->FullPathName, ".sys") || is_patchguard_protected((c_string)module->FullPathName)) continue;
		_be_pre_ob_callback_cave = find_code_cave(module->ImageBase, 13);
		if (_be_pre_ob_callback_cave != 0) {
			if (!patch_code_cave_detour(_be_pre_ob_callback_cave, (u64)&pre_operation_callback_hook)) return false;
			callback_registration->OperationRegistration->PreOperation = (POB_PRE_OPERATION_CALLBACK)_be_pre_ob_callback_cave;
			DbgPrint("[Covert Bypass]: Patched ObRegisterCallbacks \r\n");
			ExFreePoolWithTag(modules, COVERT_POOL_TAG);
			return ObRegisterCallbacks(callback_registration, registration_handle);	
			break;
		}
	}
}



void _be_patched_integrity_check() {
	return;
}

NTSTATUS _be_ps_create_system_thread(PHANDLE thread_handle, ULONG access, POBJECT_ATTRIBUTES obj_attr, HANDLE proc_handle, PCLIENT_ID client_id, PKSTART_ROUTINE start_routine, PVOID start_context) {
	//DbgPrint("[Covert Bypass]: BE called PsCreateSystemThread from 0x%p \n", _ReturnAddress());

	DbgPrint("[Covert Bypass]: Blocked BE integrity check \n");
	return PsCreateSystemThread(thread_handle, access, obj_attr, proc_handle, client_id, (PKSTART_ROUTINE)_be_patched_integrity_check, start_context);
}

PCREATE_PROCESS_NOTIFY_ROUTINE_EX _be_original_process_notify = 0;
void _be_create_process_notify_callback(PEPROCESS process, HANDLE proc_id, PPS_CREATE_NOTIFY_INFO create_info) {
	DbgPrint("Process Creation Notification: 0x%p, 0x%p, %p \n", process, proc_id, create_info);

	_be_original_process_notify(process, proc_id, create_info);	
}



NTSTATUS _be_ps_set_create_process_notify_routine_ex(PCREATE_PROCESS_NOTIFY_ROUTINE_EX notify_routine, BOOLEAN remove) {
	//DbgPrint("[Covert Bypass]: BE called PsSetCreateProcessNotifyRoutineEx from 0x%p \n", _ReturnAddress());
	_be_original_process_notify = notify_routine;

	if (remove && _be_create_process_notify_routine_code_cave != 0) {
		return PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)_be_create_process_notify_routine_code_cave, true);
	}

	PRTL_PROCESS_MODULES modules = get_loaded_module_list();
	PVOID module_base{};
	PVOID module_size{};
	void* base_address = 0;
	for (ULONG i = 0; i < modules->NumberOfModules; i++) {
		PRTL_PROCESS_MODULE_INFORMATION module = &modules->Modules[i];
		if (!strstr((c_string)module->FullPathName, ".sys") || is_patchguard_protected((c_string)module->FullPathName)) continue;
		_be_create_process_notify_routine_code_cave = find_code_cave(module->ImageBase, 13);
		if (_be_create_process_notify_routine_code_cave != 0) {
			if (!patch_code_cave_detour(_be_create_process_notify_routine_code_cave, (u64)&_be_create_process_notify_callback)) return false;

			DbgPrint("[Covert Bypass]: Patched BE process creation notifications \n");
			ExFreePoolWithTag(modules, COVERT_POOL_TAG);
			return PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)_be_create_process_notify_routine_code_cave, remove);

			break;
		}
	}

	ExFreePoolWithTag(modules, COVERT_POOL_TAG);

	return PsSetCreateProcessNotifyRoutineEx(notify_routine, remove);
}

static PCREATE_THREAD_NOTIFY_ROUTINE _be_original_thread_notify = 0;
void _be_create_thread_notify_callback(HANDLE process_id, HANDLE thread_id, BOOLEAN create) {
	//DbgPrint("Thread Creation Notification: 0x%p, 0x%p, %hhu \n", process_id, thread_id, create);

	//_be_original_thread_notify(process_id, thread_id, create);
	return;
}
NTSTATUS  _be_ps_set_create_thread_notify_routine(PCREATE_THREAD_NOTIFY_ROUTINE notify_routine) {
	//DbgPrint("[Covert Bypass]: BE called PsSetCreateThreadNotifyRoutine from 0x%p \n", _ReturnAddress());

	_be_original_thread_notify = notify_routine;

	PRTL_PROCESS_MODULES modules = get_loaded_module_list();
	PVOID module_base{};
	PVOID module_size{};
	void* base_address = 0;
	for (ULONG i = 0; i < modules->NumberOfModules; i++) {
		PRTL_PROCESS_MODULE_INFORMATION module = &modules->Modules[i];
		if (!strstr((c_string)module->FullPathName, ".sys") || is_patchguard_protected((c_string)module->FullPathName)) continue;
		_be_create_thread_notify_routine_code_cave = find_code_cave(module->ImageBase, 13);
		if (_be_create_thread_notify_routine_code_cave != 0) {
			if (!patch_code_cave_detour(_be_create_thread_notify_routine_code_cave, (u64)&_be_create_thread_notify_callback)) return false;

			DbgPrint("[Covert Bypass]: Patched BE thread creation notifications \n");
			ExFreePoolWithTag(modules, COVERT_POOL_TAG);
			return PsSetCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)_be_create_thread_notify_routine_code_cave);

			break;
		}
	}

	ExFreePoolWithTag(modules, COVERT_POOL_TAG);

	return PsSetCreateThreadNotifyRoutine(notify_routine);
}

static PLOAD_IMAGE_NOTIFY_ROUTINE _be_original_image_notify_routine = 0;
void _be_image_load_notify_callback(PUNICODE_STRING full_image_name, HANDLE proc_id, PIMAGE_INFO image_info) {
	// DbgPrint("[Covert Bypass]: Blocked BE from detecting image load: %wZ \n", full_image_name);

	//_be_original_image_notify_routine(full_image_name, proc_id, image_info);
	return;
}

NTSTATUS _be_ps_set_load_image_notify_routine(PLOAD_IMAGE_NOTIFY_ROUTINE notify_routine) {
	//DbgPrint("[Covert Bypass]: BE called PsSetLoadImageNotifyRoutine from 0x%p \n", _ReturnAddress());
	_be_original_image_notify_routine = notify_routine;

	PRTL_PROCESS_MODULES modules = get_loaded_module_list();
	PVOID module_base{};
	PVOID module_size{};
	void* base_address = 0;
	for (ULONG i = 0; i < modules->NumberOfModules; i++) {
		PRTL_PROCESS_MODULE_INFORMATION module = &modules->Modules[i];
		if (!strstr((c_string)module->FullPathName, ".sys") || is_patchguard_protected((c_string)module->FullPathName)) continue;
		_be_load_image_notify_routine_code_cave = find_code_cave(module->ImageBase, 13);
		if (_be_load_image_notify_routine_code_cave != 0) {
			if (!patch_code_cave_detour(_be_load_image_notify_routine_code_cave, (u64)&_be_image_load_notify_callback)) return false;

			DbgPrint("[Covert Bypass]: Patched BE image load notifications \n");
			ExFreePoolWithTag(modules, COVERT_POOL_TAG);
			return PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)_be_load_image_notify_routine_code_cave);

			break;
		}
	}

	ExFreePoolWithTag(modules, COVERT_POOL_TAG);

	return PsSetLoadImageNotifyRoutine(notify_routine);
}

NTSTATUS _be_ps_lookup_thread_by_threadid_hook(HANDLE ThreadId, PETHREAD* Thread) {
	UNREFERENCED_PARAMETER(ThreadId);
	UNREFERENCED_PARAMETER(Thread);

	//DbgPrint("[Covert Bypass]: [PsLookupThreadByThreadId] Blocked looking up thread: %p\r\n", ThreadId);

	return STATUS_ACCESS_VIOLATION;
}


NTSTATUS _be_zw_query_information_thread(HANDLE thread_handle, THREADINFOCLASS info_class, PVOID info, ULONG info_length, PULONG return_length) {
	DbgPrint("[Covert Bypass]: BE called ZwQueryInformationThread(0x%p, 0x%x, 0x%p, 0x%x, 0x%p) from 0x%p \n", thread_handle, info_class, info, info_length, return_length, _ReturnAddress());

	return ZwQueryInformationThread(thread_handle, info_class, info, info_length, return_length);
}

NTSTATUS _be_zw_query_system_information(SYSTEM_INFORMATION_CLASS info_class, PVOID info, ULONG info_length, PULONG return_length) {
	DbgPrint("[Covert Bypass]: BE called ZwQuerySystemInformation(0x%x, 0x%p, 0x%x, 0x%p) from 0x%p \n", info_class, info, info_length, return_length, _ReturnAddress());

	NTSTATUS query_status = ZwQuerySystemInformation(info_class, info, info_length, return_length);
	if (info_length > 0) {
		switch (info_class) {
			case 0x0B: { // SystemModuleInformation
				PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)info;

				u32 new_module_count = modules->NumberOfModules;
				for (i32 i = modules->NumberOfModules - 1; i >= 0; i--) {
					PRTL_PROCESS_MODULE_INFORMATION module = &modules->Modules[i];

					for (u32 j = 0; j < sizeof(BYPASS_WHITELISTED_DRIVER_MODULES) / sizeof(BYPASS_WHITELISTED_DRIVER_MODULES[0]); j++) {
						if (strstr((c_string)module->FullPathName, BYPASS_WHITELISTED_DRIVER_MODULES[j])) {
							DbgPrint("[Covert Bypass]: Hid module %s(%u) from BE scan \n", BYPASS_WHITELISTED_DRIVER_MODULES[j], i);
							u32 remaining_modules = (modules->NumberOfModules - 1) - i;
							if (remaining_modules > 0) {
								RtlCopyMemory(&modules->Modules[i], &modules->Modules[i + 1], remaining_modules * sizeof(PRTL_PROCESS_MODULE_INFORMATION));
							}

							new_module_count--;
						}
					}
				}

				modules->NumberOfModules = new_module_count;
			} break;

			case 0x05: { // SystemProcessInformation
				SYSTEM_PROCESS_INFORMATION* start_proc_info = (SYSTEM_PROCESS_INFORMATION*)info;
				SYSTEM_PROCESS_INFORMATION* prev_proc_info = 0;
				SYSTEM_PROCESS_INFORMATION* curr_proc_info = 0;
				SYSTEM_PROCESS_INFORMATION* next_proc_info = 0;


				curr_proc_info = start_proc_info;
				do {
					//DbgPrint("[Covert Bypass]: Detected BE enumeration on process: %wZ \n", curr_proc_info->ImageName);
					//DbgPrint("Current Proc Info 0x%p \n", curr_proc_info);
					if (curr_proc_info->NextEntryOffset == 0) {
						if (prev_proc_info != 0) {
							prev_proc_info->NextEntryOffset = 0;
						}
						break;
					}
					//DbgPrint("Next Offset: 0x%x \n", curr_proc_info->NextEntryOffset);
					next_proc_info = (SYSTEM_PROCESS_INFORMATION*)((u8*)curr_proc_info + curr_proc_info->NextEntryOffset);
					//DbgPrint("Next Proc Info 0x%p \n", next_proc_info);

					u64 whitelist_size = sizeof(BYPASS_WHITELISTED_PROCESS_MODULES) / sizeof(BYPASS_WHITELISTED_PROCESS_MODULES[0]);
					if (prev_proc_info != 0) {
						for (u64 i = 0; i < whitelist_size; i++) {
							UNICODE_STRING whitelisted_unicode_string;
							RtlInitUnicodeString(&whitelisted_unicode_string, BYPASS_WHITELISTED_PROCESS_MODULES[i]);

							if (RtlCompareUnicodeString(&curr_proc_info->ImageName, &whitelisted_unicode_string, true) == 0) {
								prev_proc_info->NextEntryOffset = prev_proc_info->NextEntryOffset + curr_proc_info->NextEntryOffset;
								DbgPrint("[Covert Bypass]: Hid process %wZ from BE scan \n", whitelisted_unicode_string);
							}

							//RtlFreeUnicodeString(&whitelisted_unicode_string);
						}
					}

					prev_proc_info = curr_proc_info;
					curr_proc_info = next_proc_info;

				} while (true);
			} break;
		}
	}
	
	return query_status;
}