#pragma once
#include <Windows.h>
#include "def.h"
#include <detours/detours.h>

/// @brief The Hooked_NtWriteVirtualMemory function is a function that hooks the 
/// NtWriteVirtualMemory function.
/// @param ProcessHandle The handle to the process.
/// @param BaseAddress The base address of the memory to write to.
/// @param Buffer The buffer to write to the memory.
/// @param NumberOfBytesToWrite The number of bytes to write to the memory.
NTSTATUS NTAPI Hooked_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress, 
    PVOID Buffer, 
    SIZE_T NumberOfBytesToWrite, 
    PSIZE_T NumberOfBytesWritten
);

/// @brief The Hooked_NtModifyBootEntry function is a function that hooks the 
/// NtModifyBootEntry function.
/// @param BootEntry The boot entry to modify.
/// @return The status of the function.
NTSTATUS NTAPI Hooked_NtModifyBootEntry(PBOOT_ENTRY BootEntry);

/// @brief The Hooked_NtMapViewOfSectionEx function is a function that hooks the 
/// NtMapViewOfSectionEx function.
/// @param SectionHandle The handle to the section.
/// @param ProcessHandle The handle to the process.
/// @param BaseAddress The base address of the memory to map.
/// @param SectionOffset The offset of the section.
/// @param ViewSize The size of the view.
/// @param AllocationType The type of allocation.
/// @param PageProtection The protection of the page.
/// @param ExtendedParameters The extended parameters.
/// @param ExtendedParameterCount The number of extended parameters.
/// @return The status of the function.
NTSTATUS NTAPI Hooked_NtMapViewOfSectionEx(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    ULONG AllocationType,
    ULONG PageProtection,
    PMEM_EXTENDED_PARAMETER ExtendedParameters,
    ULONG ExtendedParameterCount
);

/// @brief The PlaceHooks function places the hooks on the NTDLL functions.
VOID PlaceHooks();

/// @brief The UnHook function removes the hooks from the NTDLL functions.
VOID UnHook();

