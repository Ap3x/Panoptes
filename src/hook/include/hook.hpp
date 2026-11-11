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

/// @brief Hooks NtMapViewOfSection, which maps a view of a section into a process.
NTSTATUS NTAPI Hooked_NtMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    PANO_SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

/// @brief Hooks NtUnmapViewOfSection, which unmaps a view of a section from a process.
NTSTATUS NTAPI Hooked_NtUnmapViewOfSection(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

/// @brief Hooks NtUnmapViewOfSectionEx, which unmaps a view of a section from a process.
NTSTATUS NTAPI Hooked_NtUnmapViewOfSectionEx(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    ULONG Flags
);

/// @brief Hooks NtProtectVirtualMemory, which changes the protection of memory in a process.
NTSTATUS NTAPI Hooked_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtection,
    PULONG OldProtection
);

/// @brief Hooks NtAllocateVirtualMemory, which reserves and/or commits memory in a process.
NTSTATUS NTAPI Hooked_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protection
);

/// @brief Hooks NtAllocateVirtualMemoryEx, which reserves and/or commits memory in a process.
NTSTATUS NTAPI Hooked_NtAllocateVirtualMemoryEx(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG PageProtection,
    PMEM_EXTENDED_PARAMETER ExtendedParameters,
    ULONG ExtendedParameterCount
);

/// @brief Hooks NtReadVirtualMemory, which reads memory from a process.
NTSTATUS NTAPI Hooked_NtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
);

/// @brief Hooks NtCreateThreadEx, which creates a thread in a process.
NTSTATUS NTAPI Hooked_NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

/// @brief Hooks NtQueueApcThread, which queues a user-mode APC to a thread.
NTSTATUS NTAPI Hooked_NtQueueApcThread(
    HANDLE ThreadHandle,
    PPANO_APC_ROUTINE ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

/// @brief Hooks NtQueueApcThreadEx2, which queues a user-mode APC to a thread, optionally as a
/// special user APC. QueueUserAPC and QueueUserAPC2 go through it.
NTSTATUS NTAPI Hooked_NtQueueApcThreadEx2(
    HANDLE ThreadHandle,
    HANDLE ReserveHandle,
    ULONG ApcFlags,
    PPANO_APC_ROUTINE ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

/// @brief Hooks NtSetInformationProcess, which sets information about a process.
NTSTATUS NTAPI Hooked_NtSetInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
);

/// @brief The PlaceHooks function places the hooks on the NTDLL functions.
VOID PlaceHooks();

/// @brief The UnHook function removes the hooks from the NTDLL functions.
VOID UnHook();

