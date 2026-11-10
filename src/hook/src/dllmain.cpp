#include <Windows.h>
#include "hook.hpp"
#include "hook_trace.hpp"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		// Register before the hooks are placed so the first detection is not lost
		HookTraceInit();
		PlaceHooks();

		break;
	case DLL_PROCESS_DETACH:
		UnHook();
		HookTraceUninit();
		break;
	}
	return TRUE;
}

