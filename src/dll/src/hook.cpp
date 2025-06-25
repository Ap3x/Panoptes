#include "hook.hpp"
#include "detours\detours.h"

#pragma region Hooked Functions

pNtWriteVirtualMemory pOriginal_NtWriteVirtualMemory = NULL;
pNtModifyBootEntry pOriginal_NtModifyBootEntry = NULL;
pNtMapViewOfSectionEx pOriginal_NtMapViewOfSectionEx = NULL;

/// @brief The Hooked_NtWriteVirtualMemory function is a function that hooks the 
/// NtWriteVirtualMemory function.
/// @param ProcessHandle The handle to the process.
/// @param BaseAddress The base address of the memory to write to.
/// @param Buffer The buffer to write to the memory.
/// @param NumberOfBytesToWrite The number of bytes to write to the memory.
/// @param NumberOfBytesWritten The number of bytes written to the memory.
/// @return The status of the function.
NTSTATUS NTAPI Hooked_NtWriteVirtualMemory(
	HANDLE ProcessHandle, 
	PVOID BaseAddress, 
	PVOID Buffer, 
	SIZE_T NumberOfBytesToWrite, 
	PSIZE_T NumberOfBytesWritten
)
{
	NTSTATUS status = pOriginal_NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);

	return status;
}

/// @brief The Hooked_NtModifyBootEntry function is a function that hooks the 
/// NtModifyBootEntry function.
/// @param BootEntry The boot entry to modify.
/// @return The status of the function.
NTSTATUS Hooked_NtModifyBootEntry(PBOOT_ENTRY BootEntry) {
	NTSTATUS status = pOriginal_NtModifyBootEntry(BootEntry);
	return status;
}

/// @brief The Hooked_NtMapViewOfSectionEx function is a function that hooks the 
/// NtMapViewOfSectionEx function.
/// @param SectionHandle The handle to the section.
/// @param ProcessHandle The handle to the process.
/// @param BaseAddress The base address of the memory to map.
/// @param SectionOffset The offset of the section.
/// @param ViewSize The size of the view.
/// @param AllocationType The allocation type.
/// @param PageProtection The page protection.
/// @param ExtendedParameters The extended parameters.
/// @param ExtendedParameterCount The number of extended parameters.
/// @return The status of the function.
NTSTATUS Hooked_NtMapViewOfSectionEx(_In_ HANDLE SectionHandle,
	_In_ HANDLE ProcessHandle,
	_Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID* BaseAddress,
	_Inout_opt_ PLARGE_INTEGER SectionOffset,
	_Inout_ PSIZE_T ViewSize,
	_In_ ULONG AllocationType,
	_In_ ULONG PageProtection,
	_Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
	_In_ ULONG ExtendedParameterCount) 
{
	NTSTATUS status = pOriginal_NtMapViewOfSectionEx(SectionHandle,ProcessHandle,BaseAddress, 
	SectionOffset, ViewSize, AllocationType,PageProtection,ExtendedParameters,
	ExtendedParameterCount);

	return status;
}

#pragma endregion

/// @brief The PlaceHooks function places the trampoline hooks on several NTDLL functions.
VOID PlaceHooks() {
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	pOriginal_NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWriteVirtualMemory");
	if (pOriginal_NtWriteVirtualMemory)
	{
		DetourAttach((PVOID*)&pOriginal_NtWriteVirtualMemory, (PVOID)Hooked_NtWriteVirtualMemory);
	}

	pOriginal_NtModifyBootEntry = (pNtModifyBootEntry)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtModifyBootEntry");
	if (pOriginal_NtModifyBootEntry) {
		DetourAttach((PVOID*)&pOriginal_NtModifyBootEntry, (PVOID)Hooked_NtModifyBootEntry);
	}

	pOriginal_NtMapViewOfSectionEx = (pNtMapViewOfSectionEx)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtMapViewOfSectionEx");
	if (pOriginal_NtMapViewOfSectionEx) {
		DetourAttach((PVOID*)&pOriginal_NtMapViewOfSectionEx, (PVOID)Hooked_NtMapViewOfSectionEx);
	}

	DetourTransactionCommit();
	return;
}

/// @brief The UnHook function removes the trampoline hooks from the NTDLL functions.
VOID UnHook() {
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	if (pOriginal_NtWriteVirtualMemory) {
		DetourDetach((PVOID*)&pOriginal_NtWriteVirtualMemory, (PVOID)Hooked_NtWriteVirtualMemory);
	}

	if (pOriginal_NtModifyBootEntry) {
		DetourDetach((PVOID*)&pOriginal_NtModifyBootEntry, (PVOID)Hooked_NtModifyBootEntry);
	}

	if (pOriginal_NtMapViewOfSectionEx) {
		DetourDetach((PVOID*)&pOriginal_NtMapViewOfSectionEx, (PVOID)Hooked_NtMapViewOfSectionEx);
	}

	DetourTransactionCommit();
	return;
}
