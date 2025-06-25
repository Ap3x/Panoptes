#pragma once
#include <Windows.h>
#include <TraceLoggingProvider.h> 

#pragma region TraceLogging Initialization
void TraceInit();

void TraceUninit();
#pragma endregion

#pragma region Mail Slot Operations
void Log_MailSlotOpen(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName
);

void Log_MailSlotCreate(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName
);
#pragma endregion

#pragma region Named Pipe Operations
void Log_NamedPipeOpen(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName
);

void  Log_NamedPipeCreate(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName
);
#pragma endregion

#pragma region File Operations
void Log_FileSuperseded(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName
);

void Log_FileOverwritten(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName
);

void Log_FileOpen(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName,
	BOOLEAN Oplocked
);

void Log_FileCreated(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName,
	BOOLEAN Oplocked
);

void Log_FileRead(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName,
	LARGE_INTEGER FileOffset,
	ULONG ReadLength,
	BOOLEAN Compressed
);

void Log_FileWrite(
	HANDLE ProcessId,
	HANDLE ThreadId,
	PWCH FileName,
	LARGE_INTEGER FileOffset,
	ULONG ReadLength,
	BOOLEAN Compressed
);

#pragma endregion