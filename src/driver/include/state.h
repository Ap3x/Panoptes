#pragma once
#include <ntddk.h>

typedef struct _PANO_PROCESS_INFO
{
	ULONG ProcessId;
	BOOLEAN is64Bit;
	BOOLEAN Injected;
	BOOLEAN kernel32Loaded;
	BOOLEAN kernelBaseLoaded;
	BOOLEAN ntdllLoaded;
} PANO_PROCESS_INFO, * PPANO_PROCESS_INFO;

struct PanoptesState {
	LARGE_INTEGER RegistryCookie;
	RTL_AVL_TABLE Processes;
	FAST_MUTEX ProcessesLock;
	PCALLBACK_OBJECT ProcessCreateCallback;
	PVOID ImageBase;

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