#pragma once
#include "structs.h"
#include <ntddk.h>
#include <wdf.h>

#define MAX_PATH 256

EXTERN_C PVOID NTAPI RtlImageDirectoryEntryToData(
	_In_ PVOID BaseOfImage,
	_In_ BOOLEAN MappedAsImage,
	_In_ USHORT DirectoryEntry,
	_Out_ PULONG Size
);

EXTERN_C BOOLEAN NTAPI KeTestAlertThread(
	IN KPROCESSOR_MODE AlertMode
);

EXTERN_C BOOLEAN NTAPI PsIsProtectedProcess(
	_In_ PEPROCESS Process
);

#pragma pack(push, 1)
typedef struct _INJECT_SHELL
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
	WCHAR DllName[MAX_PATH];
	ULONG Tag;
	HANDLE ModuleHandle;
	PVOID ModuleFileName;
	CHAR ShellCode;
}	INJECT_SHELL, * PINJECT_SHELL;
#pragma pack(pop)

EXTERN_C POBJECT_TYPE* IoDeviceObjectType;
EXTERN_C PVOID RtlImageDirectoryEntryToData(IN PVOID Base,IN BOOLEAN MappedAsImage,IN USHORT DirectoryEntry,OUT PULONG Size);

VOID RemoveCallbacks();

NTSTATUS InitializeKernelCallbacks();
