#pragma once
#include <Winddi.h>

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
#pragma endregion