#pragma once
#include <ntifs.h>

typedef struct _PANO_PROCESS_INFO
{
	LIST_ENTRY ListEntry;
	BOOLEAN is64Bit;
	HANDLE ProcessId;
	BOOLEAN Injected;
	BOOLEAN ntdllLoaded;
	BOOLEAN kernel32Loaded;
	BOOLEAN kernelBaseLoaded;
	PVOID kernel32BaseAddress;
} PANO_PROCESS_INFO, * PPANO_PROCESS_INFO;