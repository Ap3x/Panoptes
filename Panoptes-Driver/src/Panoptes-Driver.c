#include "Panoptes-Driver.h"
#include "message.h"
#include <stdio.h>

#define PIPE_NAME L"\\??\\pipe\\Panoptes"
#define BUFFER_SIZE 1024

typedef struct _ProcessContext {
	PEPROCESS Process;
	HANDLE ProcessId;
	POBJECT_NAME_INFORMATION DosPATH;
} ProcessContext, *PProcessContext;

void KillProcess(HANDLE processHandle) {
	ZwTerminateProcess(processHandle, STATUS_SUCCESS);
}

NTSTATUS OpenPipeCommunication(PProcessContext ProcessContext) {
	UNICODE_STRING pipeName; // String containing the name of the named
	RtlInitUnicodeString(&pipeName, PIPE_NAME);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Panoptes: Initiallizing object attributes.");

	HANDLE pipeHandle;
	OBJECT_ATTRIBUTES objectAttributes = {0};
	IO_STATUS_BLOCK ioStatusBlock;

	InitializeObjectAttributes(&objectAttributes, &pipeName, OBJ_CASE_INSENSITIVE | 0x0200, 0, NULL);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Panoptes: Attempting to connect to named pipe");

	NTSTATUS status = ZwCreateFile(
		&pipeHandle,
		 FILE_WRITE_DATA | FILE_READ_DATA | SYNCHRONIZE,
		 &objectAttributes,                                       
		 &ioStatusBlock,                                
		 NULL,                                           
		 0,
		 FILE_SHARE_READ | FILE_SHARE_WRITE,             
		 FILE_OPEN,                                      
		 FILE_NON_DIRECTORY_FILE,
		 NULL,                                           
		 0                                               
	 );
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Panoptes: Failed to open named pipe: ");
		return STATUS_SUCCESS;
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Panoptes: Connected to pipe... Sending PID: %d to named pipe.", (int)(intptr_t)ProcessContext->ProcessId);

	wchar_t buffer[BUFFER_SIZE];
	ULONG bytesRead;

	// Write a response back to the named pipe
	wchar_t sendMsg[BUFFER_SIZE] = { 0 };
	swprintf_s(sendMsg, BUFFER_SIZE, L"%d : %ws\0", (int)(intptr_t)ProcessContext->ProcessId, ProcessContext->DosPATH->Name.Buffer);

	status = ZwWriteFile(
		pipeHandle,
		NULL,
		NULL,
		NULL,
		&ioStatusBlock,
		sendMsg,
		BUFFER_SIZE,
		NULL,
		NULL
	);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Panoptes: Failed to write data to named pipe: %x\n", status);
		PsTerminateSystemThread(STATUS_ABANDONED);
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Panoptes: Successfully sent PID. Attempting to read response.");

	// Read data from the named pipe
	status = ZwReadFile(
		pipeHandle,
		NULL,
		NULL,
		NULL,
		&ioStatusBlock,
		&buffer,
		BUFFER_SIZE,
		NULL,
		NULL
	);

	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Panoptes: Failed to read data from named pipe: %x\n", status);
		PsTerminateSystemThread(STATUS_ABANDONED);
	}

	status = ZwWaitForSingleObject(
		pipeHandle,
		FALSE,
		NULL
	);

	ZwClose(
		pipeHandle // Handle to the named pipe
	);

	bytesRead = (ULONG)ioStatusBlock.Information;
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Panoptes: Received message from user process: %ws\n", buffer);

	if (wcscmp(buffer, L"OK\0") == 0) {
		return STATUS_SUCCESS;
	}
	else if (wcscmp(buffer, L"NO\0") == 0) {
		return STATUS_ACCESS_DENIED;
	}
	else 
	{
		return STATUS_SUCCESS;
	}
}

VOID ImageLoadCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	PEPROCESS Process = { 0 };
	PUNICODE_STRING ProcessImageName = {0};

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Driver Loaded");

	if (FullImageName != NULL)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "DLL loaded: %ws\n", FullImageName->Buffer);
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Process ID: %d\n", (int)(intptr_t)ProcessId);
	if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process))) {
		SeLocateProcessImageName(Process, &ProcessImageName);
		if (ProcessImageName != NULL)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Process Name: %wZ\n", ProcessImageName);
			ExFreePool(ProcessImageName);
		}
		ObDereferenceObject(Process);
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Image base address: 0x%p\n", ImageInfo->ImageBase);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Image size: %d bytes\n", (int)(intptr_t)ImageInfo->ImageSize);

}

void NotifyProcesses(PEPROCESS Process, HANDLE ProcessHandle, PPS_CREATE_NOTIFY_INFO CreateInfo) {
	UNREFERENCED_PARAMETER(Process);
	UNREFERENCED_PARAMETER(ProcessHandle);
	PUNICODE_STRING processName = NULL;
	SeLocateProcessImageName(Process, &processName);


	if (CreateInfo != NULL) {
		PProcessContext pc = (PProcessContext)ExAllocatePoolWithTag(NonPagedPool, sizeof(ProcessContext), 'P');
		if (pc == NULL) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Panoptes: Error attempting to allocate process context");
			return;
		}
		pc->Process = Process;
		pc->ProcessId = ProcessHandle;
		POBJECT_NAME_INFORMATION objFileDosDeviceName;
		IoQueryFileDosDeviceName(CreateInfo->FileObject, &objFileDosDeviceName);
		pc->DosPATH = objFileDosDeviceName;
		NTSTATUS procStatus = OpenPipeCommunication(pc);

		if (NT_SUCCESS(procStatus))
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Panoptes: [+] Process was created: %wZ ", processName);
			CreateInfo->CreationStatus = STATUS_SUCCESS;
		}
		else if (procStatus == STATUS_ACCESS_DENIED)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Panoptes: [!] Proces was Denied: %wZ ", processName);
			CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
		}
		else
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Panoptes: [+] Process was created: %wZ ", processName);
			CreateInfo->CreationStatus = STATUS_SUCCESS;
		}
	}
	else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Panoptes: [-] Process was killed: %wZ ", processName);
	}
}

void UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Panoptes: Driver Entry Exit");
	PsSetCreateProcessNotifyRoutineEx(NotifyProcesses, TRUE);
	//PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);
	pDriverObject->DriverUnload = UnloadDriver;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Panoptes: Driver Entry Start");

	NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(NotifyProcesses, FALSE);
	if (status != STATUS_SUCCESS) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Panoptes: Driver Failed to Set Process Creation Notify Routine - Ensure /INTEGRITYCHECK is added to the linker options");
	}

	//NTSTATUS status = PsSetLoadImageNotifyRoutine(ImageLoadCallback);
	//if (status != STATUS_SUCCESS) {
	//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Panoptes: Driver Failed to Set Process Creation Notify Routine - Ensure /INTEGRITYCHECK is added to the linker options");
	//}
	return STATUS_SUCCESS;
}

