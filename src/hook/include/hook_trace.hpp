#pragma once
#include <Windows.h>
#include <winternl.h> // NTSTATUS

// ETW TraceLogging provider for the hook DLL, "Panoptes.Hook". It is separate from the driver's
// "Panoptes" provider: each injected process registers its own instance of this provider, and a
// consumer (the Panoptes service) tells the two sources apart by provider GUID. Detections are
// written at warning level with the HOOK_KEYWORD_DETECTION keyword.
//
// Every event carries TargetProcessId (the process acted on, 0 if the handle lacks query
// access) and Remote (whether that is another process). The process the hook ran in is the
// ProcessId the kernel stamps in the event header, which the writer cannot change.
//
// Writing an event is a single NtTraceEvent syscall, which is not hooked, so logging from inside
// a hook cannot recurse. When no trace session has enabled the provider the write is skipped.
//
// In Debug builds each event is also sent to OutputDebugString as a "[Panoptes] " message,
// which the hook tests capture.

// {D9AA2FDD-2853-4A97-A42F-E77E42921704}
#define HOOK_PROVIDER_NAME "Panoptes.Hook"

#define HOOK_KEYWORD_DETECTION 0x1

/// @brief Registers the provider. Call before placing the hooks.
VOID HookTraceInit();

/// @brief Unregisters the provider. Call after removing the hooks.
VOID HookTraceUninit();

/// @brief NtWriteVirtualMemory wrote a PE image. Event "PEWritten".
/// @param ProcessHandle The process written to.
/// @param CurrentProcess Whether ProcessHandle is the current process.
/// @param BaseAddress Where the image was written.
/// @param Executable Whether the destination memory is executable.
VOID Log_PEWritten(HANDLE ProcessHandle, BOOL CurrentProcess, PVOID BaseAddress, BOOL Executable);

/// @brief NtWriteVirtualMemory wrote to a process's PEB. Event "PEBWritten".
/// @param ProcessHandle The process written to.
/// @param CurrentProcess Whether ProcessHandle is the current process.
/// @param Size The number of bytes written.
/// @param PebOffset The offset of the write from the start of the PEB.
VOID Log_PEBWritten(HANDLE ProcessHandle, BOOL CurrentProcess, SIZE_T Size, ULONG_PTR PebOffset);

/// @brief NtReadVirtualMemory read from a process's PEB. Event "PEBRead".
/// @param ProcessHandle The process read from.
/// @param CurrentProcess Whether ProcessHandle is the current process.
/// @param Size The number of bytes read.
/// @param PebOffset The offset of the read from the start of the PEB.
VOID Log_PEBRead(HANDLE ProcessHandle, BOOL CurrentProcess, SIZE_T Size, ULONG_PTR PebOffset);

/// @brief NtSetInformationProcess was called to set a process's protection level
/// (ProcessProtectionInformation). Only the kernel may do this, so the call is expected to fail;
/// the attempt itself is the signal. Event "ProtectionSetAttempt".
/// @param ProcessHandle The process whose protection was to be set.
/// @param CurrentProcess Whether ProcessHandle is the current process.
/// @param Status The NTSTATUS the call returned.
VOID Log_ProtectionSetAttempt(HANDLE ProcessHandle, BOOL CurrentProcess, NTSTATUS Status);

/// @brief NtQueueApcThread or NtQueueApcThreadEx2 queued an APC to a thread. Event "ApcQueued".
/// TargetProcessId is the process that owns the thread; the event also carries TargetThreadId.
/// @param ThreadHandle The thread the APC was queued to.
/// @param CurrentProcess Whether the thread is in the current process.
/// @param Api The name of the hooked function.
/// @param ApcRoutine The routine the APC runs.
/// @param ApcFlags The QUEUE_USER_APC_FLAGS_* values (0x1 for a special user APC, which runs
/// without the thread entering an alertable wait); always 0 for NtQueueApcThread.
VOID Log_ApcQueued(HANDLE ThreadHandle, BOOL CurrentProcess, const char* Api, PVOID ApcRoutine, ULONG ApcFlags);

/// @brief NtCreateThreadEx created a thread in another process. Event "RemoteThreadCreated".
/// @param ProcessHandle The process the thread was created in.
/// @param StartRoutine The address the thread starts executing at.
/// @param CreateFlags The THREAD_CREATE_FLAGS_* values, e.g. 0x1 for a suspended thread.
VOID Log_RemoteThreadCreated(HANDLE ProcessHandle, PVOID StartRoutine, ULONG CreateFlags);

/// @brief NtAllocateVirtualMemory or NtAllocateVirtualMemoryEx allocated executable memory.
/// Event "ExecutableAllocated".
/// @param ProcessHandle The process the memory was allocated in.
/// @param CurrentProcess Whether ProcessHandle is the current process.
/// @param Api The name of the hooked function.
/// @param BaseAddress The base of the allocation, as returned by the kernel.
/// @param RegionSize The size of the allocation, rounded up to whole pages.
/// @param AllocationType The MEM_* allocation flags.
/// @param Protection The PAGE_* protection.
VOID Log_ExecutableAllocated(HANDLE ProcessHandle, BOOL CurrentProcess, const char* Api,
	PVOID BaseAddress, SIZE_T RegionSize, ULONG AllocationType, ULONG Protection);

/// @brief NtUnmapViewOfSection or NtUnmapViewOfSectionEx unmapped a view with executable pages.
/// Unmapping an image from another process is the first step of process hollowing.
/// Event "ExecutableUnmapped".
/// @param ProcessHandle The process the view was unmapped from.
/// @param CurrentProcess Whether ProcessHandle is the current process.
/// @param Api The name of the hooked function.
/// @param BaseAddress The address passed to the unmap call.
/// @param Image Whether the view was a mapped image (MEM_IMAGE).
VOID Log_ExecutableUnmapped(HANDLE ProcessHandle, BOOL CurrentProcess, const char* Api,
	PVOID BaseAddress, BOOL Image);

/// @brief NtMapViewOfSection or NtMapViewOfSectionEx mapped a view into another process. Mapping
/// a shared section into a target is a way to inject code without NtWriteVirtualMemory.
/// Event "RemoteViewMapped".
/// @param ProcessHandle The process the view was mapped into.
/// @param Api The name of the hooked function.
/// @param BaseAddress The base of the view, as returned by the kernel.
/// @param ViewSize The size of the view, as returned by the kernel.
/// @param Protection The protection the caller requested.
/// @param Executable Whether any committed page of the view is executable.
/// @param Image Whether the view is a mapped image (MEM_IMAGE).
VOID Log_RemoteViewMapped(HANDLE ProcessHandle, const char* Api, PVOID BaseAddress, SIZE_T ViewSize,
	ULONG Protection, BOOL Executable, BOOL Image);

/// @brief NtProtectVirtualMemory made a region starting with a PE image executable.
/// Event "PEMadeExecutable".
/// @param ProcessHandle The process whose memory was reprotected.
/// @param CurrentProcess Whether ProcessHandle is the current process.
/// @param BaseAddress The start of the region.
/// @param OldProtection The previous protection, or 0 if the caller did not ask for it.
/// @param NewProtection The new protection.
VOID Log_PEMadeExecutable(HANDLE ProcessHandle, BOOL CurrentProcess, PVOID BaseAddress,
	ULONG OldProtection, ULONG NewProtection);
