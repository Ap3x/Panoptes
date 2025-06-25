#include "panoptes_trace.h"

#pragma region TraceLogging Initialization
// {7036AF95-9DAF-4486-8D93-7005D45A6A06}
TRACELOGGING_DEFINE_PROVIDER(g_hPanoCommonProvider, "Panoptes",
	(0x7036af95, 0x9daf, 0x4486, 0x8d, 0x93, 0x70, 0x5, 0xd4, 0x5a, 0x6a, 0x6));

void TraceInit()
{
	TraceLoggingRegister(g_hPanoCommonProvider);
}

void TraceUninit()
{
	TraceLoggingUnregister(g_hPanoCommonProvider);
}
#pragma endregion

#pragma region Mail Slot Operations
/// @brief Log a mail slot open event
/// @param ProcessId The ID of the process that opened the mail slot
/// @param ThreadId The ID of the thread that opened the mail slot
/// @param FileName The name of the mail slot
void Log_MailSlotOpen(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName
)
{
	TraceLoggingWrite(g_hPanoCommonProvider, "MailSlotOpen",
		TraceLoggingValue(ProcessId, "SourceProcessId"),
		TraceLoggingValue(ThreadId, "SourceThreadId"),
		TraceLoggingWideString(FileName, "MailSlotName"));
}

/// @brief Log a mail slot create event
/// @param ProcessId The ID of the process that created the mail slot
/// @param ThreadId The ID of the thread that created the mail slot
/// @param FileName The name of the mail slot
void Log_MailSlotCreate(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName
)
{
	TraceLoggingWrite(g_hPanoCommonProvider, "MailSlotCreate",
		TraceLoggingValue(ProcessId, "SourceProcessId"),
		TraceLoggingValue(ThreadId, "SourceThreadId"),
		TraceLoggingWideString(FileName, "MailSlotName"));
}
#pragma endregion

#pragma region Named Pipe Operations
/// @brief Log a named pipe create event
/// @param ProcessId The ID of the process that created the named pipe
/// @param ThreadId The ID of the thread that created the named pipe
/// @param FileName The name of the named pipe
void Log_NamedPipeCreate(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName
)
{
	TraceLoggingWrite(g_hPanoCommonProvider, "NamedPipeCreate",
		TraceLoggingValue(ProcessId, "SourceProcessId"),
		TraceLoggingValue(ThreadId, "SourceThreadId"),
		TraceLoggingWideString(FileName, "NamedPipeName"));
}

/// @brief Log a named pipe open event
/// @param ProcessId The ID of the process that opened the named pipe
/// @param ThreadId The ID of the thread that opened the named pipe
/// @param FileName The name of the named pipe
void Log_NamedPipeOpen(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName
)
{
	TraceLoggingWrite(g_hPanoCommonProvider, "NamedPipeOpen",
		TraceLoggingValue(ProcessId, "SourceProcessId"),
		TraceLoggingValue(ThreadId, "SourceThreadId"),
		TraceLoggingWideString(FileName, "NamedPipeName"));
}
#pragma endregion

#pragma region File Operations

/// @brief Log a file create event
/// @param ProcessId The ID of the process that created the file
/// @param ThreadId The ID of the thread that created the file
/// @param FileName The name of the file
/// @param Oplocked Whether the file is oplocked
void Log_FileCreated(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName,
	BOOLEAN Oplocked
)
{
	TraceLoggingWrite(g_hPanoCommonProvider, "FileCreated",
		TraceLoggingValue(ProcessId, "SourceProcessId"),
		TraceLoggingValue(ThreadId, "SourceThreadId"),
		TraceLoggingWideString(FileName, "FileName"),
		TraceLoggingBool(Oplocked, "Oplocked"));
}

/// @brief Log a file open event
/// @param ProcessId The ID of the process that opened the file
/// @param ThreadId The ID of the thread that opened the file
/// @param FileName The name of the file
/// @param Oplocked Whether the file is oplocked
void Log_FileOpen(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName,
	BOOLEAN Oplocked
)
{
	TraceLoggingWrite(g_hPanoCommonProvider, "FileOpened",
		TraceLoggingValue(ProcessId, "SourceProcessId"),
		TraceLoggingValue(ThreadId, "SourceThreadId"),
		TraceLoggingWideString(FileName, "FileName"),
		TraceLoggingBool(Oplocked, "Oplocked"));
}

/// @brief Log a file overwrite event
/// @param ProcessId The ID of the process that overwrote the file
/// @param ThreadId The ID of the thread that overwrote the file
/// @param FileName The name of the file
void Log_FileOverwritten(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName
)
{
	TraceLoggingWrite(g_hPanoCommonProvider, "FileOverwritten",
		TraceLoggingValue(ProcessId, "SourceProcessId"),
		TraceLoggingValue(ThreadId, "SourceThreadId"),
		TraceLoggingWideString(FileName, "FileName"));
}

/// @brief Log a file read event
/// @param ProcessId The ID of the process that read the file
/// @param ThreadId The ID of the thread that read the file
/// @param FileName The name of the file
/// @param FileOffset The offset of the file
/// @param ReadLength The length of the read
/// @param Compressed Whether the file is compressed
void Log_FileRead(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName,
	LARGE_INTEGER FileOffset,
	ULONG ReadLength,
	BOOLEAN Compressed
)
{
	TraceLoggingWrite(g_hPanoCommonProvider, "FileRead",
		TraceLoggingValue(ProcessId, "SourceProcessId"),
		TraceLoggingValue(ThreadId, "SourceThreadId"),
		TraceLoggingWideString(FileName, "FileName"),
		TraceLoggingULong(ReadLength, "ReadLength"),
		TraceLoggingValue(FileOffset.QuadPart, "FileOffset"),
		TraceLoggingBoolean(Compressed, "CompressedFile"));
}

/// @brief Log a file write event
/// @param ProcessId The ID of the process that wrote the file
/// @param ThreadId The ID of the thread that wrote the file
/// @param FileName The name of the file
/// @param FileOffset The offset of the file
/// @param ReadLength The length of the write
/// @param Compressed Whether the file is compressed
void Log_FileWrite(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName,
	LARGE_INTEGER FileOffset,
	ULONG ReadLength,
	BOOLEAN Compressed
)
{
	TraceLoggingWrite(g_hPanoCommonProvider, "FileWrite",
		TraceLoggingValue(ProcessId, "SourceProcessId"),
		TraceLoggingValue(ThreadId, "SourceThreadId"),
		TraceLoggingWideString(FileName, "FileName"),
		TraceLoggingULong(ReadLength, "WriteLength"),
		TraceLoggingValue(FileOffset.QuadPart, "FileOffset"),
		TraceLoggingBoolean(Compressed, "CompressedFile"));
}

/// @brief Log a file superseded event
/// @param ProcessId The ID of the process that superseded the file
/// @param ThreadId The ID of the thread that superseded the file
/// @param FileName The name of the file
void Log_FileSuperseded(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName
)
{
	TraceLoggingWrite(g_hPanoCommonProvider, "FileSuperseded",
		TraceLoggingValue(ProcessId, "SourceProcessId"),
		TraceLoggingValue(ThreadId, "SourceThreadId"),
		TraceLoggingWideString(FileName, "FileName"));
}

#pragma endregion