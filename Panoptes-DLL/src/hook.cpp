#include "hook.hpp"
#include "vt_yara.hpp"

vt_yara objCpy;
CRITICAL_SECTION cs;
hook::pNtWriteVirtualMemory pOriginalNtWriteVirtualMemory = NULL;

#pragma region Hooked Functions
DWORD hook::HookedNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
{
	EnterCriticalSection(&cs);

	if (vt_yara::ScanMem(BaseAddress, NumberOfBytesToWrite, objCpy.rules))
	{
		MessageBoxW(NULL, L"GOTEM", L"Panoptes", 0);
		//pipe::SendDetection();
	}

	DWORD status = pOriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
	LeaveCriticalSection(&cs);
	return status;
}
#pragma endregion

VOID hook::PlaceHooks(vt_yara obj) {
	InitializeCriticalSection(&cs);
	objCpy = obj;
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	pOriginalNtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWriteVirtualMemory");
	DetourAttach((PVOID*)&pOriginalNtWriteVirtualMemory, (PVOID)hook::HookedNtWriteVirtualMemory);
	DetourTransactionCommit();
	return;
}

VOID hook::UnHook() {
	EnterCriticalSection(&cs);
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	DetourDetach((PVOID*)&pOriginalNtWriteVirtualMemory, (PVOID)HookedNtWriteVirtualMemory);
	DetourTransactionCommit();

	LeaveCriticalSection(&cs);
	DeleteCriticalSection(&cs);
	return;
}
