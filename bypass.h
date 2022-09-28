#pragma once

#include "types.h"
#include "memory.h"
#include "hook.h"

#include "be.h"
#include "eac.h"
#include "eos.h"
#include "ricochet.h"

typedef enum Anticheat_Type {
	Anticheat_Type_Undefined = 0,

	Anticheat_Type_BE,
	Anticheat_Type_EAC,
	Anticheat_Type_EAC_EOS,
	Anticheat_Type_RICOCHET,

	Anticheat_Type_Count
} Anticheat_Type; 

static const c_string BYPASS_WHITELISTED_DRIVER_MODULES[]  = { "CovertBypass.sys", "gdrv.sys", "iqvw64e.sys"};
static const u16*     BYPASS_WHITELISTED_PROCESS_MODULES[] = { 
	L"TestInjectionPayload.dll",
	L"UniverseLib.Mono.dll", 
	L"UnityExplorer.ML.Mono.dll", 
	L"Extreme Injector v3.exe", 
	L"cheatengine-x86_64-SSE4-AVX2.exe",
	L"injector.exe",
	L"payload.dll",
	L"windbg.exe",
	L"ida.exe",
	L"ida64.exe",
	L"CheatGear.exe",
	L"winlister.exe",
	L"dbgview64.exe",
	L"ReClass.NET.exe",
	L"NVIDIA_REFLEX_64.exe",
	L"ProcessHacker.exe",
	L"command.exe",
	L"MelonLoader.dll",
	L"dnSpy.exe",
	L"MInject.dll",
	L"MInjector.exe",
};

COVERT_API void bypass_cleanup();
COVERT_API bool bypass_initialize(DRIVER_OBJECT* driver);