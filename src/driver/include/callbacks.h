#pragma once
#include "structs.h"
#include <ntddk.h>
#include <ntimage.h>
#include <wdf.h>

#define MAX_PATH 256

typedef struct _PROCESS_MITIGATION_POLICY_INFORMATION
{
	PROCESS_MITIGATION_POLICY Policy;
	union
	{
		PROCESS_MITIGATION_ASLR_POLICY ASLRPolicy;
		PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY StrictHandleCheckPolicy;
		PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY SystemCallDisablePolicy;
		PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ExtensionPointDisablePolicy;
		PROCESS_MITIGATION_DYNAMIC_CODE_POLICY DynamicCodePolicy;
		PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY ControlFlowGuardPolicy;
		PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY SignaturePolicy;
		PROCESS_MITIGATION_FONT_DISABLE_POLICY FontDisablePolicy;
		PROCESS_MITIGATION_IMAGE_LOAD_POLICY ImageLoadPolicy;
		PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY SystemCallFilterPolicy;
		PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY PayloadRestrictionPolicy;
		PROCESS_MITIGATION_CHILD_PROCESS_POLICY ChildProcessPolicy;
		PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY SideChannelIsolationPolicy;
		PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY UserShadowStackPolicy;
		PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY RedirectionTrustPolicy;
		PROCESS_MITIGATION_USER_POINTER_AUTH_POLICY UserPointerAuthPolicy;
		PROCESS_MITIGATION_SEHOP_POLICY SEHOPPolicy;
	}Data;
} PROCESS_MITIGATION_POLICY_INFORMATION, * PPROCESS_MITIGATION_POLICY_INFORMATION;


extern "C" NTSTATUS NTAPI ZwQueryInformationProcess(
	HANDLE hProcess, 
	PROCESSINFOCLASS infoType, 
	/*out*/ PVOID pBuf, 
	/*sizeof pBuf*/ ULONG lenBuf, 
	SIZE_T* /*PULONG*/ returnLength
);

extern "C" PVOID NTAPI RtlImageDirectoryEntryToData(
	_In_ PVOID BaseOfImage,
	_In_ BOOLEAN MappedAsImage,
	_In_ USHORT DirectoryEntry,
	_Out_ PULONG Size
);

// Undocumented kernel APC API, exported by ntoskrnl but not declared in the WDK
typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT, * PKAPC_ENVIRONMENT;

typedef VOID(NTAPI* PKNORMAL_ROUTINE)(
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2);

typedef VOID(NTAPI* PKKERNEL_ROUTINE)(
	_In_ PRKAPC Apc,
	_Inout_opt_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_opt_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2);

typedef VOID(NTAPI* PKRUNDOWN_ROUTINE)(_In_ PRKAPC Apc);

extern "C" VOID NTAPI KeInitializeApc(
	_Out_ PRKAPC Apc,
	_In_ PRKTHREAD Thread,
	_In_ KAPC_ENVIRONMENT Environment,
	_In_ PKKERNEL_ROUTINE KernelRoutine,
	_In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
	_In_opt_ PKNORMAL_ROUTINE NormalRoutine,
	_In_opt_ KPROCESSOR_MODE ProcessorMode,
	_In_opt_ PVOID NormalContext);

extern "C" BOOLEAN NTAPI KeInsertQueueApc(
	_Inout_ PRKAPC Apc,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2,
	_In_ KPRIORITY Increment);

extern "C" BOOLEAN NTAPI KeTestAlertThread(
	IN KPROCESSOR_MODE AlertMode
);

/// @brief Exported by ntoskrnl but not declared in the WDK. Returns the process's WOW64 PEB
/// (non-NULL) for a 32-bit process running under WOW64, or NULL for a native 64-bit process.
extern "C" NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(
	_In_ PEPROCESS Process
);

extern "C" BOOLEAN NTAPI PsIsProtectedProcess(
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

extern "C" POBJECT_TYPE* IoDeviceObjectType;
//extern "C" PVOID RtlFindExportedRoutineByName(PVOID DllBase,PCHAR RoutineName);
EXTERN_C PVOID RtlImageDirectoryEntryToData(IN PVOID Base,
	IN BOOLEAN MappedAsImage,
	IN USHORT DirectoryEntry,
	OUT PULONG Size);

VOID RemoveCallbacks();
NTSTATUS InitializeKernelCallbacks();
