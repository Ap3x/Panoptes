#pragma once
#include <ntifs.h>

typedef struct _PANO_PROCESS_INFO
{
	BOOLEAN is64Bit;
	HANDLE ProcessId;
	BOOLEAN Injected;
	BOOLEAN ProtectedProcess;
	BOOLEAN SignedImagesOnly; // Signature policy rejects the hook DLL, so it is not injected
	BOOLEAN InjectionExcluded; // Image name is in the DontInject list, so it is not injected
	BOOLEAN ntdllLoaded;
	BOOLEAN kernel32Loaded;
	BOOLEAN kernelBaseLoaded;
	PVOID kernel32BaseAddress;
} PANO_PROCESS_INFO, * PPANO_PROCESS_INFO;