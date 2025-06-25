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

#pragma region Mail Slot Operations
void Log_MailSlotOpen(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName
)
{
	TraceLoggingWrite(g_hPanoProvider, "MailSlotOpen",
		TraceLoggingValue(ProcessId, "SourceProcessId"),
		TraceLoggingValue(ThreadId, "SourceThreadId"),
		TraceLoggingWideString(FileName, "MailSlotName"));
}

void Log_MailSlotCreate(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName
)
{
	TraceLoggingWrite(g_hPanoProvider, "MailSlotCreate",
		TraceLoggingValue(ProcessId, "SourceProcessId"),
		TraceLoggingValue(ThreadId, "SourceThreadId"),
		TraceLoggingWideString(FileName, "MailSlotName"));
}
#pragma endregion

#pragma region Named Pipe Operations
void Log_NamedPipeCreate(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName
)
{
	TraceLoggingWrite(g_hPanoProvider, "NamedPipeCreate",
		TraceLoggingValue(ProcessId, "SourceProcessId"),
		TraceLoggingValue(ThreadId, "SourceThreadId"),
		TraceLoggingWideString(FileName, "NamedPipeName"));
}

void Log_NamedPipeOpen(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName
)
{
	TraceLoggingWrite(g_hPanoProvider, "NamedPipeOpen",
		TraceLoggingValue(ProcessId, "SourceProcessId"),
		TraceLoggingValue(ThreadId, "SourceThreadId"),
		TraceLoggingWideString(FileName, "NamedPipeName"));
}
#pragma endregion

#pragma region File Operations

void Log_FileCreated(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName,
	BOOLEAN Oplocked
)
{
	TraceLoggingWrite(g_hPanoProvider, "FileCreated",
		TraceLoggingValue(ProcessId, "SourceProcessId"),
		TraceLoggingValue(ThreadId, "SourceThreadId"),
		TraceLoggingWideString(FileName, "FileName"),
		TraceLoggingBool(Oplocked, "Oplocked"));
}

void Log_FileOpen(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName,
	BOOLEAN Oplocked
)
{
	TraceLoggingWrite(g_hPanoProvider, "FileOpened",
		TraceLoggingValue(ProcessId, "SourceProcessId"),
		TraceLoggingValue(ThreadId, "SourceThreadId"),
		TraceLoggingWideString(FileName, "FileName"),
		TraceLoggingBool(Oplocked, "Oplocked"));
}

void Log_FileOverwritten(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName
)
{
	TraceLoggingWrite(g_hPanoProvider, "FileOverwritten",
		TraceLoggingValue(ProcessId, "SourceProcessId"),
		TraceLoggingValue(ThreadId, "SourceThreadId"),
		TraceLoggingWideString(FileName, "FileName"));
}

void Log_FileRead(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName,
	LARGE_INTEGER FileOffset,
	ULONG ReadLength,
	BOOLEAN Compressed
)
{
	TraceLoggingWrite(g_hPanoProvider, "FileRead",
		TraceLoggingValue(ProcessId, "SourceProcessId"),
		TraceLoggingValue(ThreadId, "SourceThreadId"),
		TraceLoggingWideString(FileName, "FileName"),
		TraceLoggingULong(ReadLength, "ReadLength"),
		TraceLoggingValue(FileOffset.QuadPart, "FileOffset"),
		TraceLoggingBoolean(Compressed, "CompressedFile"));
}

void Log_FileWrite(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName,
	LARGE_INTEGER FileOffset,
	ULONG ReadLength,
	BOOLEAN Compressed
)
{
	TraceLoggingWrite(g_hPanoProvider, "FileWrite",
		TraceLoggingValue(ProcessId, "SourceProcessId"),
		TraceLoggingValue(ThreadId, "SourceThreadId"),
		TraceLoggingWideString(FileName, "FileName"),
		TraceLoggingULong(ReadLength, "WriteLength"),
		TraceLoggingValue(FileOffset.QuadPart, "FileOffset"),
		TraceLoggingBoolean(Compressed, "CompressedFile"));
}

void Log_FileSuperseded(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName
)
{
	TraceLoggingWrite(g_hPanoProvider, "FileSuperseded",
		TraceLoggingValue(ProcessId, "SourceProcessId"),
		TraceLoggingValue(ThreadId, "SourceThreadId"),
		TraceLoggingWideString(FileName, "FileName"));
}

#pragma endregion