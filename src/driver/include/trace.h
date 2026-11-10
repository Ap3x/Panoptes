#pragma once
#include <wdm.h>
#include <TraceLoggingProvider.h> 

#pragma region TraceLogging Initialization
void TraceInit();

void TraceUninit();
#pragma endregion

#pragma region Driver Operations
void Log_DriverEntry(
	PDRIVER_OBJECT  DriverObject,
	PUNICODE_STRING RegistryPath
);

void Log_DriverExit(
	PDRIVER_OBJECT  DriverObject
);
#pragma endregion
