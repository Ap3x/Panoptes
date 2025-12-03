#pragma once
#include <fltKernel.h>
#include <ntddk.h>

typedef struct _PANO_PROCESS_INFO
{
	ULONG ProcessId;
	BOOLEAN Injected;
	BOOLEAN Kernel32Loaded;
	BOOLEAN KernelBaseLoaded;
	BOOLEAN NtdllLoaded;
	BOOLEAN Wow64Loaded;
	BOOLEAN MitigationPolicyBan;
	PVOID Kernel32ImageBase;
} PANO_PROCESS_INFO, * PPANO_PROCESS_INFO;

struct PanoptesState {
	LARGE_INTEGER RegistryCookie;
	RTL_AVL_TABLE Processes;
	FAST_MUTEX ProcessesLock;
	PCALLBACK_OBJECT ProcessCreateCallback;
	PFLT_FILTER FilterHandle;
	UNICODE_STRING g_symLink;
	UNICODE_STRING g_SymbolicLinkName;

	NTSTATUS Init();
	void Term();

private:
	static RTL_GENERIC_COMPARE_RESULTS ProcessCompare(
		_In_ PRTL_AVL_TABLE Table,
		_In_ PVOID FirstStruct,
		_In_ PVOID SecondStruct);

	static PVOID TableAlloc(
		_In_ struct _RTL_AVL_TABLE* Table,
		_In_ CLONG ByteSize);

	static VOID	TableFree(
		_In_ struct _RTL_AVL_TABLE* Table,
		_In_ __drv_freesMem(Mem) _Post_invalid_ PVOID Buffer);
};