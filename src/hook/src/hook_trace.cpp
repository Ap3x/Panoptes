#include "hook_trace.hpp"
#include <TraceLoggingProvider.h>
#include <winmeta.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

#pragma region TraceLogging Initialization
// {D9AA2FDD-2853-4A97-A42F-E77E42921704}
TRACELOGGING_DEFINE_PROVIDER(g_hHookProvider, HOOK_PROVIDER_NAME,
	(0xd9aa2fdd, 0x2853, 0x4a97, 0xa4, 0x2f, 0xe7, 0x7e, 0x42, 0x92, 0x17, 0x04));

VOID HookTraceInit()
{
	TraceLoggingRegister(g_hHookProvider);
}

VOID HookTraceUninit()
{
	TraceLoggingUnregister(g_hHookProvider);
}
#pragma endregion

/// @brief Sends a "[Panoptes] " message to OutputDebugString in Debug builds.
static VOID DebugMessage(const char* Format, ...)
{
#ifdef _DEBUG
	char message[192];
	va_list args;
	va_start(args, Format);
	_vsnprintf_s(message, _TRUNCATE, Format, args);
	va_end(args);
	OutputDebugStringA(message);
#else
	UNREFERENCED_PARAMETER(Format);
#endif
}

#pragma region Detections
VOID Log_PEWritten(HANDLE ProcessHandle, BOOL CurrentProcess, PVOID BaseAddress, BOOL Executable)
{
	TraceLoggingWrite(g_hHookProvider, "PEWritten",
		TraceLoggingLevel(WINEVENT_LEVEL_WARNING),
		TraceLoggingKeyword(HOOK_KEYWORD_DETECTION),
		TraceLoggingString("NtWriteVirtualMemory", "Api"),
		TraceLoggingUInt32(GetProcessId(ProcessHandle), "TargetProcessId"),
		TraceLoggingBool(!CurrentProcess, "Remote"),
		TraceLoggingPointer(BaseAddress, "BaseAddress"),
		TraceLoggingBool(Executable, "Executable"));

	DebugMessage("[Panoptes] NtWriteVirtualMemory: PE image written to %p in the %s process, destination %s\n",
		BaseAddress, CurrentProcess ? "current" : "remote", Executable ? "executable" : "not executable");
}

VOID Log_PEBWritten(HANDLE ProcessHandle, BOOL CurrentProcess, SIZE_T Size, ULONG_PTR PebOffset)
{
	TraceLoggingWrite(g_hHookProvider, "PEBWritten",
		TraceLoggingLevel(WINEVENT_LEVEL_WARNING),
		TraceLoggingKeyword(HOOK_KEYWORD_DETECTION),
		TraceLoggingString("NtWriteVirtualMemory", "Api"),
		TraceLoggingUInt32(GetProcessId(ProcessHandle), "TargetProcessId"),
		TraceLoggingBool(!CurrentProcess, "Remote"),
		TraceLoggingUInt64((UINT64)Size, "Size"),
		TraceLoggingHexUInt64((UINT64)PebOffset, "PebOffset"));

	DebugMessage("[Panoptes] NtWriteVirtualMemory: %Iu bytes written to the PEB of the %s process at offset 0x%Ix\n",
		Size, CurrentProcess ? "current" : "remote", PebOffset);
}

VOID Log_PEBRead(HANDLE ProcessHandle, BOOL CurrentProcess, SIZE_T Size, ULONG_PTR PebOffset)
{
	// Debuggers, Task Manager and Process Explorer read other processes' PEBs routinely, so this
	// is informational rather than a warning
	TraceLoggingWrite(g_hHookProvider, "PEBRead",
		TraceLoggingLevel(WINEVENT_LEVEL_INFO),
		TraceLoggingKeyword(HOOK_KEYWORD_DETECTION),
		TraceLoggingString("NtReadVirtualMemory", "Api"),
		TraceLoggingUInt32(GetProcessId(ProcessHandle), "TargetProcessId"),
		TraceLoggingBool(!CurrentProcess, "Remote"),
		TraceLoggingUInt64((UINT64)Size, "Size"),
		TraceLoggingHexUInt64((UINT64)PebOffset, "PebOffset"));

	DebugMessage("[Panoptes] NtReadVirtualMemory: %Iu bytes read from the PEB of the %s process at offset 0x%Ix\n",
		Size, CurrentProcess ? "current" : "remote", PebOffset);
}

VOID Log_ProtectionSetAttempt(HANDLE ProcessHandle, BOOL CurrentProcess, NTSTATUS Status)
{
	TraceLoggingWrite(g_hHookProvider, "ProtectionSetAttempt",
		TraceLoggingLevel(WINEVENT_LEVEL_WARNING),
		TraceLoggingKeyword(HOOK_KEYWORD_DETECTION),
		TraceLoggingString("NtSetInformationProcess", "Api"),
		TraceLoggingUInt32(GetProcessId(ProcessHandle), "TargetProcessId"),
		TraceLoggingBool(!CurrentProcess, "Remote"),
		TraceLoggingNTStatus(Status, "Status"));

	DebugMessage("[Panoptes] NtSetInformationProcess: attempt to set the protection of the %s process, status 0x%08lx\n",
		CurrentProcess ? "current" : "remote", (ULONG)Status);
}

VOID Log_ApcQueued(HANDLE ThreadHandle, BOOL CurrentProcess, const char* Api, PVOID ApcRoutine, ULONG ApcFlags)
{
	TraceLoggingWrite(g_hHookProvider, "ApcQueued",
		TraceLoggingLevel(WINEVENT_LEVEL_WARNING),
		TraceLoggingKeyword(HOOK_KEYWORD_DETECTION),
		TraceLoggingString(Api, "Api"),
		TraceLoggingUInt32(GetProcessIdOfThread(ThreadHandle), "TargetProcessId"),
		TraceLoggingBool(!CurrentProcess, "Remote"),
		TraceLoggingUInt32(GetThreadId(ThreadHandle), "TargetThreadId"),
		TraceLoggingPointer(ApcRoutine, "ApcRoutine"),
		TraceLoggingHexUInt32(ApcFlags, "ApcFlags"));

	DebugMessage("[Panoptes] %s: APC queued to a thread in the %s process, routine %p, flags 0x%lx\n",
		Api, CurrentProcess ? "current" : "remote", ApcRoutine, ApcFlags);
}

VOID Log_RemoteThreadCreated(HANDLE ProcessHandle, PVOID StartRoutine, ULONG CreateFlags)
{
	TraceLoggingWrite(g_hHookProvider, "RemoteThreadCreated",
		TraceLoggingLevel(WINEVENT_LEVEL_WARNING),
		TraceLoggingKeyword(HOOK_KEYWORD_DETECTION),
		TraceLoggingString("NtCreateThreadEx", "Api"),
		TraceLoggingUInt32(GetProcessId(ProcessHandle), "TargetProcessId"),
		TraceLoggingBool(TRUE, "Remote"),
		TraceLoggingPointer(StartRoutine, "StartRoutine"),
		TraceLoggingHexUInt32(CreateFlags, "CreateFlags"));

	DebugMessage("[Panoptes] NtCreateThreadEx: thread created in a remote process, start %p, flags 0x%lx\n",
		StartRoutine, CreateFlags);
}

VOID Log_ExecutableAllocated(HANDLE ProcessHandle, BOOL CurrentProcess, const char* Api,
	PVOID BaseAddress, SIZE_T RegionSize, ULONG AllocationType, ULONG Protection)
{
	TraceLoggingWrite(g_hHookProvider, "ExecutableAllocated",
		TraceLoggingLevel(WINEVENT_LEVEL_WARNING),
		TraceLoggingKeyword(HOOK_KEYWORD_DETECTION),
		TraceLoggingString(Api, "Api"),
		TraceLoggingUInt32(GetProcessId(ProcessHandle), "TargetProcessId"),
		TraceLoggingBool(!CurrentProcess, "Remote"),
		TraceLoggingPointer(BaseAddress, "BaseAddress"),
		TraceLoggingUInt64((UINT64)RegionSize, "RegionSize"),
		TraceLoggingHexUInt32(AllocationType, "AllocationType"),
		TraceLoggingHexUInt32(Protection, "Protection"));

	DebugMessage("[Panoptes] %s: %Iu executable bytes allocated at %p in the %s process (protection 0x%lx)\n",
		Api, RegionSize, BaseAddress, CurrentProcess ? "current" : "remote", Protection);
}

VOID Log_ExecutableUnmapped(HANDLE ProcessHandle, BOOL CurrentProcess, const char* Api,
	PVOID BaseAddress, BOOL Image)
{
	TraceLoggingWrite(g_hHookProvider, "ExecutableUnmapped",
		TraceLoggingLevel(WINEVENT_LEVEL_WARNING),
		TraceLoggingKeyword(HOOK_KEYWORD_DETECTION),
		TraceLoggingString(Api, "Api"),
		TraceLoggingUInt32(GetProcessId(ProcessHandle), "TargetProcessId"),
		TraceLoggingBool(!CurrentProcess, "Remote"),
		TraceLoggingPointer(BaseAddress, "BaseAddress"),
		TraceLoggingBool(Image, "Image"));

	DebugMessage("[Panoptes] %s: executable %s at %p unmapped from the %s process\n",
		Api, Image ? "image" : "view", BaseAddress, CurrentProcess ? "current" : "remote");
}

VOID Log_RemoteViewMapped(HANDLE ProcessHandle, const char* Api, PVOID BaseAddress, SIZE_T ViewSize,
	ULONG Protection, BOOL Executable, BOOL Image)
{
	TraceLoggingWrite(g_hHookProvider, "RemoteViewMapped",
		TraceLoggingLevel(WINEVENT_LEVEL_WARNING),
		TraceLoggingKeyword(HOOK_KEYWORD_DETECTION),
		TraceLoggingString(Api, "Api"),
		TraceLoggingUInt32(GetProcessId(ProcessHandle), "TargetProcessId"),
		TraceLoggingBool(TRUE, "Remote"),
		TraceLoggingPointer(BaseAddress, "BaseAddress"),
		TraceLoggingUInt64((UINT64)ViewSize, "ViewSize"),
		TraceLoggingHexUInt32(Protection, "Protection"),
		TraceLoggingBool(Executable, "Executable"),
		TraceLoggingBool(Image, "Image"));

	DebugMessage("[Panoptes] %s: %Iu-byte %s mapped into a remote process at %p (protection 0x%lx, %s)\n",
		Api, ViewSize, Image ? "image" : "view", BaseAddress, Protection,
		Executable ? "executable" : "not executable");
}

VOID Log_PEMadeExecutable(HANDLE ProcessHandle, BOOL CurrentProcess, PVOID BaseAddress,
	ULONG OldProtection, ULONG NewProtection)
{
	TraceLoggingWrite(g_hHookProvider, "PEMadeExecutable",
		TraceLoggingLevel(WINEVENT_LEVEL_WARNING),
		TraceLoggingKeyword(HOOK_KEYWORD_DETECTION),
		TraceLoggingString("NtProtectVirtualMemory", "Api"),
		TraceLoggingUInt32(GetProcessId(ProcessHandle), "TargetProcessId"),
		TraceLoggingBool(!CurrentProcess, "Remote"),
		TraceLoggingPointer(BaseAddress, "BaseAddress"),
		TraceLoggingHexUInt32(OldProtection, "OldProtection"),
		TraceLoggingHexUInt32(NewProtection, "NewProtection"));

	DebugMessage("[Panoptes] NtProtectVirtualMemory: PE image at %p in the %s process made executable (0x%lx -> 0x%lx)\n",
		BaseAddress, CurrentProcess ? "current" : "remote", OldProtection, NewProtection);
}
#pragma endregion
