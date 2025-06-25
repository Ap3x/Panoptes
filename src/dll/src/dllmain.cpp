#include <Windows.h>
#include "hook.hpp"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		PlaceHooks();

		break;
	case DLL_PROCESS_DETACH:
		UnHook();
		break;
	}
	return TRUE;
}

