#pragma once
#include <Winddi.h>
#include <winternl.h>

/// @brief The BOOT_ENTRY structure represents a boot entry in the boot configuration database.
/// https://doxygen.reactos.org/d6/d0e/ndk_2iotypes_8h_source.html#l01140
typedef struct _BOOT_ENTRY
{
    ULONG Version;
    ULONG Length;
    ULONG Id;
    ULONG Attributes;
    ULONG FriendlyNameOffset;
    ULONG BootFilePathOffset;
    ULONG OsOptionsLength;
    CHAR OsOptions[1];
} BOOT_ENTRY, *PBOOT_ENTRY;

#pragma region API Definitions
/// @brief The NtWriteVirtualMemory function writes memory to a specified process.
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
    );

/// @brief The NtModifyBootEntry function modifies a boot entry in the boot configuration database.
typedef NTSTATUS(NTAPI* pNtModifyBootEntry)(
    PBOOT_ENTRY BootEntry
    );

/// @brief The NtMapViewOfSectionEx function maps a view of a section into the address space of a 
/// process.
typedef NTSTATUS(NTAPI* pNtMapViewOfSectionEx)(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) 
                _Post_readable_byte_size_(*ViewSize)) PVOID* BaseAddress,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
    );

/// @brief How a mapped view is shared with child processes. Only defined in kernel-mode headers.
typedef enum _PANO_SECTION_INHERIT {
    PanoViewShare = 1,
    PanoViewUnmap = 2
} PANO_SECTION_INHERIT;

/// @brief The NtMapViewOfSection function maps a view of a section into the address space of a
/// process.
typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ PANO_SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect
    );

/// @brief The NtUnmapViewOfSection function unmaps a view of a section from the address space of
/// a process.
typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress
    );

/// @brief The NtUnmapViewOfSectionEx function unmaps a view of a section from the address space
/// of a process, with MEM_UNMAP_* flags.
typedef NTSTATUS(NTAPI* pNtUnmapViewOfSectionEx)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ ULONG Flags
    );

/// @brief The NtProtectVirtualMemory function changes the protection of memory in a process.
typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtection,
    _Out_ PULONG OldProtection
    );

/// @brief The NtAllocateVirtualMemory function reserves and/or commits memory in a process.
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protection
    );

/// @brief The NtAllocateVirtualMemoryEx function reserves and/or commits memory in a process,
/// with extended parameters.
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemoryEx)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
    );

/// @brief The NtReadVirtualMemory function reads memory from a specified process.
typedef NTSTATUS(NTAPI* pNtReadVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _Out_writes_bytes_(NumberOfBytesToRead) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToRead,
    _Out_opt_ PSIZE_T NumberOfBytesRead
    );

/// @brief The NtCreateThreadEx function creates a thread in a specified process.
/// StartRoutine is a PUSER_THREAD_START_ROUTINE and AttributeList a PPS_ATTRIBUTE_LIST, neither
/// of which is in the SDK headers.
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags,
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PVOID AttributeList
    );

/// @brief The routine an APC queued with NtQueueApcThread runs. Not in the SDK headers.
typedef VOID(NTAPI* PPANO_APC_ROUTINE)(
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
    );

/// @brief The NtQueueApcThread function queues a user-mode APC to a thread.
typedef NTSTATUS(NTAPI* pNtQueueApcThread)(
    _In_ HANDLE ThreadHandle,
    _In_ PPANO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
    );

/// @brief QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC: the APC is delivered without the thread having
/// to enter an alertable wait.
#define PANO_QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC 0x1

/// @brief The NtQueueApcThreadEx2 function queues a user-mode APC to a thread, optionally as a
/// special user APC. Exported by ntdll on Windows 10 2004 and later; KernelBase's QueueUserAPC
/// and QueueUserAPC2 call it.
typedef NTSTATUS(NTAPI* pNtQueueApcThreadEx2)(
    _In_ HANDLE ThreadHandle,
    _In_opt_ HANDLE ReserveHandle,
    _In_ ULONG ApcFlags,
    _In_ PPANO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
    );

/// @brief The NtSetInformationProcess function sets information about a process.
typedef NTSTATUS(NTAPI* pNtSetInformationProcess)(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength
    );
#pragma endregion