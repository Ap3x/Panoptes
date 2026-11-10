#include "trace.h"

PDRIVER_OBJECT  g_DriverObject;

#pragma region TraceLogging Initialization
// {7036AF95-9DAF-4486-8D93-7005D45A6A06}
TRACELOGGING_DEFINE_PROVIDER(g_hPanoProvider, "Panoptes",
	(0x7036af95, 0x9daf, 0x4486, 0x8d, 0x93, 0x70, 0x5, 0xd4, 0x5a, 0x6a, 0x6));

void TraceInit()
{
	TraceLoggingRegister(g_hPanoProvider);
}

void TraceUninit()
{
	TraceLoggingUnregister(g_hPanoProvider);
}
#pragma endregion

#pragma region Driver Operations
void Log_DriverEntry(
	PDRIVER_OBJECT  DriverObject,
	PUNICODE_STRING RegistryPath
)
{
	g_DriverObject = DriverObject;

	TraceLoggingWrite(g_hPanoProvider, "PanoptesStart",
		TraceLoggingPointer(DriverObject),
		TraceLoggingUnicodeString(RegistryPath, "RegPath"));
}

void Log_DriverExit(
	PDRIVER_OBJECT  DriverObject
)
{
	TraceLoggingWrite(g_hPanoProvider, "PanoptesExit",
		TraceLoggingPointer(DriverObject));
}
#pragma endregion