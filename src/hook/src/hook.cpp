#include "hook.hpp"
#include "hook_trace.hpp"
#include "detours\detours.h"
#include "winternl.h"

#pragma region Hooked Functions

pNtWriteVirtualMemory pOriginal_NtWriteVirtualMemory = NULL;
pNtMapViewOfSection pOriginal_NtMapViewOfSection = NULL;
pNtMapViewOfSectionEx pOriginal_NtMapViewOfSectionEx = NULL;
pNtUnmapViewOfSection pOriginal_NtUnmapViewOfSection = NULL;
pNtUnmapViewOfSectionEx pOriginal_NtUnmapViewOfSectionEx = NULL;
pNtProtectVirtualMemory pOriginal_NtProtectVirtualMemory = NULL;
pNtAllocateVirtualMemory pOriginal_NtAllocateVirtualMemory = NULL;
pNtAllocateVirtualMemoryEx pOriginal_NtAllocateVirtualMemoryEx = NULL;
pNtReadVirtualMemory pOriginal_NtReadVirtualMemory = NULL;
pNtCreateThreadEx pOriginal_NtCreateThreadEx = NULL;
pNtQueueApcThread pOriginal_NtQueueApcThread = NULL;
pNtQueueApcThreadEx2 pOriginal_NtQueueApcThreadEx2 = NULL;
pNtSetInformationProcess pOriginal_NtSetInformationProcess = NULL;

/// @brief Checks whether a buffer starts with the "MZ" magic bytes of a PE image.
/// @param Buffer The buffer to check.
/// @param Size The number of readable bytes in Buffer.
/// @return TRUE if the buffer starts with "MZ".
static BOOL ContainsDOSSignature(const BYTE *Buffer, SIZE_T Size)
{
	if (Buffer == NULL || Size < sizeof(WORD))
	{
		return FALSE;
	}

	__try
	{
		return *(const WORD *)Buffer == IMAGE_DOS_SIGNATURE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}
}

/// @brief Checks whether a page protection allows execution.
/// @param Protection A PAGE_* value, optionally with modifiers such as PAGE_GUARD.
/// @return TRUE for PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE and
/// PAGE_EXECUTE_WRITECOPY.
static BOOL IsExecutableProtection(ULONG Protection)
{
	return (Protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

/// @brief Checks whether an address in a process is committed, executable memory.
/// @param ProcessHandle The process the address is in. Needs PROCESS_QUERY_INFORMATION or
/// PROCESS_QUERY_LIMITED_INFORMATION; if the query fails the memory is reported as not executable.
/// @param Address The address to check.
/// @return TRUE if the page containing Address is executable.
static BOOL IsExecutableMemory(HANDLE ProcessHandle, PVOID Address)
{
	MEMORY_BASIC_INFORMATION mbi{};
	if (VirtualQueryEx(ProcessHandle, Address, &mbi, sizeof(mbi)) != sizeof(mbi))
	{
		return FALSE;
	}
	return mbi.State == MEM_COMMIT && IsExecutableProtection(mbi.Protect);
}

/// @brief Checks whether the mapped view containing an address has any executable pages. The
/// whole view is walked, because an image view's first page is its read-only PE header and the
/// executable sections come after it. Must be called before the view is unmapped.
/// @param ProcessHandle The process the view is in. Needs PROCESS_QUERY_INFORMATION or
/// PROCESS_QUERY_LIMITED_INFORMATION; if the query fails the view is reported as not executable.
/// @param Address An address inside the view.
/// @param IsImage Receives whether the view is a mapped image (MEM_IMAGE).
/// @return TRUE if any committed page of the view is executable.
static BOOL ViewContainsExecutable(HANDLE ProcessHandle, PVOID Address, BOOL *IsImage)
{
	*IsImage = FALSE;

	MEMORY_BASIC_INFORMATION mbi{};
	if (VirtualQueryEx(ProcessHandle, Address, &mbi, sizeof(mbi)) != sizeof(mbi) || mbi.State == MEM_FREE)
	{
		return FALSE;
	}
	*IsImage = (mbi.Type == MEM_IMAGE);

	// Every region of the view shares its AllocationBase; the walk stops at the first one that
	// does not, including the free region after the view
	PVOID allocationBase = mbi.AllocationBase;
	BYTE *next = (BYTE *)allocationBase;
	while (VirtualQueryEx(ProcessHandle, next, &mbi, sizeof(mbi)) == sizeof(mbi) &&
		   mbi.AllocationBase == allocationBase)
	{
		if (mbi.State == MEM_COMMIT && IsExecutableProtection(mbi.Protect))
		{
			return TRUE;
		}
		next = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
	}
	return FALSE;
}

/// @brief Checks whether a process handle refers to the current process.
/// @param ProcessHandle The process. Needs PROCESS_QUERY_LIMITED_INFORMATION unless it is the
/// current-process pseudo-handle; if the query fails the process is treated as remote.
/// @return TRUE if the handle is for the current process.
static BOOL IsCurrentProcess(HANDLE ProcessHandle)
{
	if (ProcessHandle == GetCurrentProcess())
	{
		return TRUE;
	}

	// GetProcessId returns 0 on failure, which never matches a real process ID
	return GetProcessId(ProcessHandle) == GetCurrentProcessId();
}

/// @brief Checks whether a thread belongs to the current process.
/// @param ThreadHandle The thread. Needs THREAD_QUERY_LIMITED_INFORMATION unless it is the
/// current-thread pseudo-handle; if the query fails the thread is treated as remote.
/// @return TRUE if the thread is in the current process.
static BOOL IsThreadInCurrentProcess(HANDLE ThreadHandle)
{
	if (ThreadHandle == GetCurrentThread())
	{
		return TRUE;
	}

	// GetProcessIdOfThread returns 0 on failure, which never matches a real process ID
	return GetProcessIdOfThread(ThreadHandle) == GetCurrentProcessId();
}

/// The kernel gives each PEB its own page-aligned page, and the PEB is smaller than a page
/// on every supported Windows version, so a write into that page is a write into the PEB.
#define PANO_PEB_SPAN 0x1000

/// NtQueryInformationProcess, resolved in PlaceHooks. It is not hooked, so calling it from a hook
/// cannot recurse.
static decltype(&NtQueryInformationProcess) g_NtQueryInformationProcess = NULL;

/// @brief Gets the PEB addresses of a process. A WOW64 process has two: its native 64-bit PEB
/// and its 32-bit PEB. From a WOW64 caller (the x86 hook DLL) only the 32-bit PEB is visible,
/// which is the one a 32-bit target's code uses.
/// @param ProcessHandle The process. Needs PROCESS_QUERY_LIMITED_INFORMATION unless it is the
/// current-process pseudo-handle.
/// @param Pebs Receives up to two PEB addresses; unused entries are set to 0.
static VOID GetPebAddresses(HANDLE ProcessHandle, ULONG_PTR Pebs[2])
{
	Pebs[0] = Pebs[1] = 0;

	if (ProcessHandle == GetCurrentProcess())
	{
		Pebs[0] = (ULONG_PTR)NtCurrentTeb()->ProcessEnvironmentBlock;
		return;
	}

	if (g_NtQueryInformationProcess == NULL)
	{
		return;
	}

	PROCESS_BASIC_INFORMATION info{};
	if (NT_SUCCESS(g_NtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &info, sizeof(info), NULL)))
	{
		Pebs[0] = (ULONG_PTR)info.PebBaseAddress;
	}

#ifdef _WIN64
	// A WOW64 target's 32-bit code uses its 32-bit PEB; this returns 0 for a native target
	ULONG_PTR peb32 = 0;
	if (NT_SUCCESS(g_NtQueryInformationProcess(ProcessHandle, ProcessWow64Information, &peb32, sizeof(peb32), NULL)))
	{
		Pebs[1] = peb32;
	}
#endif
}

/// @brief Checks whether a memory range in a process overlaps one of its PEBs.
/// @param ProcessHandle The process the range is in.
/// @param Address The start of the range.
/// @param Size The size of the range in bytes.
/// @param PebOffset Receives the offset into the PEB where the overlap starts.
/// @return TRUE if the range overlaps a PEB of the process.
static BOOL RangeTouchesPEB(HANDLE ProcessHandle, PVOID Address, SIZE_T Size, ULONG_PTR *PebOffset)
{
	ULONG_PTR pebs[2];
	GetPebAddresses(ProcessHandle, pebs);

	const ULONG_PTR start = (ULONG_PTR)Address;
	const ULONG_PTR end = (Size > MAXULONG_PTR - start) ? MAXULONG_PTR : start + Size;

	for (ULONG_PTR peb : pebs)
	{
		if (peb != 0 && start < peb + PANO_PEB_SPAN && end > peb)
		{
			*PebOffset = (start > peb) ? start - peb : 0;
			return TRUE;
		}
	}
	return FALSE;
}

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
	PSIZE_T NumberOfBytesWritten)
{
	NTSTATUS status = pOriginal_NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	BOOL currentProcess = IsCurrentProcess(ProcessHandle);
	ULONG_PTR pebOffset = 0;
	if (RangeTouchesPEB(ProcessHandle, BaseAddress, NumberOfBytesToWrite, &pebOffset))
	{
		Log_PEBWritten(ProcessHandle, currentProcess, NumberOfBytesToWrite, pebOffset);
	}

	if (ContainsDOSSignature((const BYTE *)Buffer, NumberOfBytesToWrite))
	{
		Log_PEWritten(ProcessHandle, currentProcess, BaseAddress, IsExecutableMemory(ProcessHandle, BaseAddress));
	}

	return status;
}

/// @brief Hooks NtProtectVirtualMemory.
/// @param ProcessHandle The handle to the process.
/// @param BaseAddress The base address of the region.
/// @param RegionSize The size of the region.
/// @param NewProtection The new page protection.
/// @param OldProtection Receives the previous page protection.
/// @return The status of the function.
NTSTATUS NTAPI Hooked_NtProtectVirtualMemory(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	PSIZE_T RegionSize,
	ULONG NewProtection,
	PULONG OldProtection)
{
	NTSTATUS status = pOriginal_NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize,
													   NewProtection, OldProtection);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (IsExecutableProtection(NewProtection))
	{
		Log_PEMadeExecutable(ProcessHandle, IsCurrentProcess(ProcessHandle), *BaseAddress,
							 (OldProtection != NULL) ? *OldProtection : 0, NewProtection);
	}

	return status;
}

/// @brief Hooks NtMapViewOfSection.
/// @param SectionHandle The handle to the section.
/// @param ProcessHandle The handle to the process the view is mapped into.
/// @param BaseAddress The base address of the view.
/// @param ZeroBits The number of high-order address bits that must be zero.
/// @param CommitSize The number of bytes to commit initially.
/// @param SectionOffset The offset of the view within the section.
/// @param ViewSize The size of the view.
/// @param InheritDisposition How the view is shared with child processes.
/// @param AllocationType The allocation type.
/// @param Win32Protect The page protection.
/// @return The status of the function.
NTSTATUS NTAPI Hooked_NtMapViewOfSection(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	PANO_SECTION_INHERIT InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect)
{
	NTSTATUS status = pOriginal_NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress,
												   ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType,
												   Win32Protect);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (!IsCurrentProcess(ProcessHandle))
	{
		// On success the kernel has written the view's actual base and size back to the caller
		BOOL isImage = FALSE;
		const BOOL executable = ViewContainsExecutable(ProcessHandle, *BaseAddress, &isImage);
		Log_RemoteViewMapped(ProcessHandle, "NtMapViewOfSection", *BaseAddress, *ViewSize,
							 Win32Protect, executable, isImage);
	}

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
NTSTATUS NTAPI Hooked_NtMapViewOfSectionEx(_In_ HANDLE SectionHandle,
										   _In_ HANDLE ProcessHandle,
										   _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID *BaseAddress,
										   _Inout_opt_ PLARGE_INTEGER SectionOffset,
										   _Inout_ PSIZE_T ViewSize,
										   _In_ ULONG AllocationType,
										   _In_ ULONG PageProtection,
										   _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
										   _In_ ULONG ExtendedParameterCount)
{
	NTSTATUS status = pOriginal_NtMapViewOfSectionEx(SectionHandle, ProcessHandle, BaseAddress,
													 SectionOffset, ViewSize, AllocationType, PageProtection, ExtendedParameters,
													 ExtendedParameterCount);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (!IsCurrentProcess(ProcessHandle))
	{
		BOOL isImage = FALSE;
		const BOOL executable = ViewContainsExecutable(ProcessHandle, *BaseAddress, &isImage);
		Log_RemoteViewMapped(ProcessHandle, "NtMapViewOfSectionEx", *BaseAddress, *ViewSize,
							 PageProtection, executable, isImage);
	}

	return status;
}

/// @brief Hooks NtUnmapViewOfSection.
/// @param ProcessHandle The handle to the process the view is unmapped from.
/// @param BaseAddress The base address of the view.
/// @return The status of the function.
NTSTATUS NTAPI Hooked_NtUnmapViewOfSection(
	HANDLE ProcessHandle,
	PVOID BaseAddress)
{
	// Queried before the call: once unmapped, the view's protection is gone
	BOOL isImage = FALSE;
	const BOOL executable = ViewContainsExecutable(ProcessHandle, BaseAddress, &isImage);

	NTSTATUS status = pOriginal_NtUnmapViewOfSection(ProcessHandle, BaseAddress);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (executable)
	{
		Log_ExecutableUnmapped(ProcessHandle, IsCurrentProcess(ProcessHandle), "NtUnmapViewOfSection",
							   BaseAddress, isImage);
	}

	return status;
}

/// @brief Hooks NtUnmapViewOfSectionEx.
/// @param ProcessHandle The handle to the process the view is unmapped from.
/// @param BaseAddress The base address of the view.
/// @param Flags MEM_UNMAP_* flags.
/// @return The status of the function.
NTSTATUS NTAPI Hooked_NtUnmapViewOfSectionEx(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	ULONG Flags)
{
	// Queried before the call: once unmapped, the view's protection is gone
	BOOL isImage = FALSE;
	const BOOL executable = ViewContainsExecutable(ProcessHandle, BaseAddress, &isImage);

	NTSTATUS status = pOriginal_NtUnmapViewOfSectionEx(ProcessHandle, BaseAddress, Flags);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (executable)
	{
		Log_ExecutableUnmapped(ProcessHandle, IsCurrentProcess(ProcessHandle), "NtUnmapViewOfSectionEx",
							   BaseAddress, isImage);
	}

	return status;
}

/// @brief Hooks NtAllocateVirtualMemory.
/// @param ProcessHandle The handle to the process.
/// @param BaseAddress The base address of the region.
/// @param ZeroBits The number of high-order address bits that must be zero.
/// @param RegionSize The size of the region.
/// @param AllocationType MEM_* allocation flags.
/// @param Protection The page protection.
/// @return The status of the function.
NTSTATUS NTAPI Hooked_NtAllocateVirtualMemory(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protection)
{
	NTSTATUS status = pOriginal_NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits,
														RegionSize, AllocationType, Protection);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// On success the kernel has written the actual base and rounded-up size back to the caller
	if (IsExecutableProtection(Protection))
	{
		Log_ExecutableAllocated(ProcessHandle, IsCurrentProcess(ProcessHandle), "NtAllocateVirtualMemory",
								*BaseAddress, *RegionSize, AllocationType, Protection);
	}

	return status;
}

/// @brief Hooks NtAllocateVirtualMemoryEx.
/// @param ProcessHandle The handle to the process.
/// @param BaseAddress The base address of the region.
/// @param RegionSize The size of the region.
/// @param AllocationType MEM_* allocation flags.
/// @param PageProtection The page protection.
/// @param ExtendedParameters The extended parameters.
/// @param ExtendedParameterCount The number of extended parameters.
/// @return The status of the function.
NTSTATUS NTAPI Hooked_NtAllocateVirtualMemoryEx(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG PageProtection,
	PMEM_EXTENDED_PARAMETER ExtendedParameters,
	ULONG ExtendedParameterCount)
{
	NTSTATUS status = pOriginal_NtAllocateVirtualMemoryEx(ProcessHandle, BaseAddress, RegionSize,
														  AllocationType, PageProtection, ExtendedParameters, ExtendedParameterCount);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (IsExecutableProtection(PageProtection))
	{
		Log_ExecutableAllocated(ProcessHandle, IsCurrentProcess(ProcessHandle), "NtAllocateVirtualMemoryEx",
								*BaseAddress, *RegionSize, AllocationType, PageProtection);
	}

	return status;
}

/// @brief Hooks NtReadVirtualMemory.
/// @param ProcessHandle The handle to the process.
/// @param BaseAddress The base address of the memory to read.
/// @param Buffer Receives the memory read.
/// @param NumberOfBytesToRead The number of bytes to read.
/// @param NumberOfBytesRead Receives the number of bytes read.
/// @return The status of the function.
NTSTATUS NTAPI Hooked_NtReadVirtualMemory(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T NumberOfBytesToRead,
	PSIZE_T NumberOfBytesRead)
{
	NTSTATUS status = pOriginal_NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer,
													NumberOfBytesToRead, NumberOfBytesRead);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	ULONG_PTR pebOffset = 0;
	if (RangeTouchesPEB(ProcessHandle, BaseAddress, NumberOfBytesToRead, &pebOffset))
	{
		Log_PEBRead(ProcessHandle, IsCurrentProcess(ProcessHandle), NumberOfBytesToRead, pebOffset);
	}

	return status;
}

/// @brief Hooks NtCreateThreadEx.
/// @param ThreadHandle Receives the handle to the new thread.
/// @param DesiredAccess The access requested for the thread handle.
/// @param ObjectAttributes The attributes of the thread object.
/// @param ProcessHandle The handle to the process the thread is created in.
/// @param StartRoutine The address the thread starts executing at.
/// @param Argument The argument passed to StartRoutine.
/// @param CreateFlags THREAD_CREATE_FLAGS_* values.
/// @param ZeroBits The number of high-order address bits of the stack that must be zero.
/// @param StackSize The initial committed stack size.
/// @param MaximumStackSize The maximum stack size.
/// @param AttributeList The PS_ATTRIBUTE_LIST for the thread.
/// @return The status of the function.
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
	PVOID AttributeList)
{
	NTSTATUS status = pOriginal_NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes,
												 ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize,
												 AttributeList);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// ThreadHandle is an out-parameter (PHANDLE), and the new handle may lack query access, so the
	// target is taken from ProcessHandle
	if (!IsCurrentProcess(ProcessHandle))
	{
		Log_RemoteThreadCreated(ProcessHandle, StartRoutine, CreateFlags);
	}

	return status;
}

/// @brief Hooks NtQueueApcThread.
/// @param ThreadHandle The handle to the thread the APC is queued to.
/// @param ApcRoutine The routine the APC runs.
/// @param ApcArgument1 The first argument passed to ApcRoutine.
/// @param ApcArgument2 The second argument passed to ApcRoutine.
/// @param ApcArgument3 The third argument passed to ApcRoutine.
/// @return The status of the function.
NTSTATUS NTAPI Hooked_NtQueueApcThread(
	HANDLE ThreadHandle,
	PPANO_APC_ROUTINE ApcRoutine,
	PVOID ApcArgument1,
	PVOID ApcArgument2,
	PVOID ApcArgument3)
{
	NTSTATUS status = pOriginal_NtQueueApcThread(ThreadHandle, ApcRoutine, ApcArgument1,
												 ApcArgument2, ApcArgument3);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (!IsThreadInCurrentProcess(ThreadHandle))
	{
		Log_ApcQueued(ThreadHandle, FALSE, "NtQueueApcThread", (PVOID)ApcRoutine, 0);
	}

	return status;
}

/// @brief Hooks NtQueueApcThreadEx2.
/// @param ThreadHandle The handle to the thread the APC is queued to.
/// @param ReserveHandle An optional APC reserve object.
/// @param ApcFlags QUEUE_USER_APC_FLAGS_* values, e.g. 0x1 for a special user APC.
/// @param ApcRoutine The routine the APC runs. For QueueUserAPC this is ntdll's dispatcher, which
/// calls the caller's routine (passed in ApcArgument1).
/// @param ApcArgument1 The first argument passed to ApcRoutine.
/// @param ApcArgument2 The second argument passed to ApcRoutine.
/// @param ApcArgument3 The third argument passed to ApcRoutine.
/// @return The status of the function.
NTSTATUS NTAPI Hooked_NtQueueApcThreadEx2(
	HANDLE ThreadHandle,
	HANDLE ReserveHandle,
	ULONG ApcFlags,
	PPANO_APC_ROUTINE ApcRoutine,
	PVOID ApcArgument1,
	PVOID ApcArgument2,
	PVOID ApcArgument3)
{
	NTSTATUS status = pOriginal_NtQueueApcThreadEx2(ThreadHandle, ReserveHandle, ApcFlags, ApcRoutine,
													ApcArgument1, ApcArgument2, ApcArgument3);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (!IsThreadInCurrentProcess(ThreadHandle))
	{
		Log_ApcQueued(ThreadHandle, FALSE, "NtQueueApcThreadEx2", (PVOID)ApcRoutine, ApcFlags);
	}

	return status;
}

/// The native PROCESSINFOCLASS value for a process's PS_PROTECTION, which winternl.h does not
/// define. Not to be confused with the Win32 ProcessProtectionLevelInfo, a different enum in
/// which 7 means ProcessDebugPort here.
#define PANO_PROCESS_PROTECTION_INFORMATION 61

/// @brief Hooks NtSetInformationProcess.
/// @param ProcessHandle The handle to the process.
/// @param ProcessInformationClass The kind of information being set.
/// @param ProcessInformation The information to set.
/// @param ProcessInformationLength The size of ProcessInformation in bytes.
/// @return The status of the function.
NTSTATUS NTAPI Hooked_NtSetInformationProcess(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength)
{
	NTSTATUS status = pOriginal_NtSetInformationProcess(ProcessHandle, ProcessInformationClass,
														ProcessInformation, ProcessInformationLength);

	if (ProcessInformationClass == (PROCESSINFOCLASS)PANO_PROCESS_PROTECTION_INFORMATION)
	{
		Log_ProtectionSetAttempt(ProcessHandle, IsCurrentProcess(ProcessHandle), status);
	}

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return status;
}

#pragma endregion

/// @brief An ntdll export and the hook placed on it. Original receives the export's address
/// and, once attached, points at the Detours trampoline that calls the real function.
struct HOOK_ENTRY
{
	const char *Name;
	PVOID *Original;
	PVOID Hook;
};

static HOOK_ENTRY g_Hooks[] = {
	{"NtWriteVirtualMemory", (PVOID *)&pOriginal_NtWriteVirtualMemory, (PVOID)Hooked_NtWriteVirtualMemory},
	{"NtMapViewOfSection", (PVOID *)&pOriginal_NtMapViewOfSection, (PVOID)Hooked_NtMapViewOfSection},
	{"NtMapViewOfSectionEx", (PVOID *)&pOriginal_NtMapViewOfSectionEx, (PVOID)Hooked_NtMapViewOfSectionEx},
	{"NtUnmapViewOfSection", (PVOID *)&pOriginal_NtUnmapViewOfSection, (PVOID)Hooked_NtUnmapViewOfSection},
	{"NtUnmapViewOfSectionEx", (PVOID *)&pOriginal_NtUnmapViewOfSectionEx, (PVOID)Hooked_NtUnmapViewOfSectionEx},
	{"NtProtectVirtualMemory", (PVOID *)&pOriginal_NtProtectVirtualMemory, (PVOID)Hooked_NtProtectVirtualMemory},
	{"NtAllocateVirtualMemory", (PVOID *)&pOriginal_NtAllocateVirtualMemory, (PVOID)Hooked_NtAllocateVirtualMemory},
	{"NtAllocateVirtualMemoryEx", (PVOID *)&pOriginal_NtAllocateVirtualMemoryEx, (PVOID)Hooked_NtAllocateVirtualMemoryEx},
	{"NtReadVirtualMemory", (PVOID *)&pOriginal_NtReadVirtualMemory, (PVOID)Hooked_NtReadVirtualMemory},
	{"NtCreateThreadEx", (PVOID *)&pOriginal_NtCreateThreadEx, (PVOID)Hooked_NtCreateThreadEx},
	{"NtQueueApcThread", (PVOID *)&pOriginal_NtQueueApcThread, (PVOID)Hooked_NtQueueApcThread},
	{"NtQueueApcThreadEx2", (PVOID *)&pOriginal_NtQueueApcThreadEx2, (PVOID)Hooked_NtQueueApcThreadEx2},
	{"NtSetInformationProcess", (PVOID *)&pOriginal_NtSetInformationProcess, (PVOID)Hooked_NtSetInformationProcess},
};

/// @brief The PlaceHooks function places the trampoline hooks on several NTDLL functions.
/// Exports missing from this version of ntdll (e.g. the Ex variants on older Windows) are skipped.
VOID PlaceHooks()
{
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	g_NtQueryInformationProcess = (decltype(&NtQueryInformationProcess))GetProcAddress(ntdll, "NtQueryInformationProcess");

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	for (HOOK_ENTRY &hook : g_Hooks)
	{
		*hook.Original = (PVOID)GetProcAddress(ntdll, hook.Name);
		if (*hook.Original != NULL)
		{
			DetourAttach(hook.Original, hook.Hook);
		}
	}

	DetourTransactionCommit();
	return;
}

/// @brief The UnHook function removes the trampoline hooks from the NTDLL functions.
VOID UnHook()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	for (HOOK_ENTRY &hook : g_Hooks)
	{
		if (*hook.Original != NULL)
		{
			DetourDetach(hook.Original, hook.Hook);
		}
	}

	DetourTransactionCommit();
	return;
}
