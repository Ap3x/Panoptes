#include "filter.h"
#include "trace.h"
#include "state.h"

PFLT_FILTER FilterHandle{};


NTSTATUS FilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
	PAGED_CODE();
	NTSTATUS status;

	if (FilterHandle == nullptr) {
		status = STATUS_SUCCESS;
	}
	else {
		if (Flags == FLTFL_FILTER_UNLOAD_MANDATORY) {
			FltUnregisterFilter(FilterHandle);
			status = STATUS_SUCCESS;
		}
		else {
			status = STATUS_FLT_DO_NOT_DETACH;
		}
	}

	return status;
}

const FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),			//  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags
	NULL,								//  Context Registration.
	Callbacks,                          //  Operation callbacks
	FilterUnload,						//  FilterUnload
	NULL,                               //  InstanceSetup
	NULL,                               //  InstanceQueryTeardown
	NULL,                               //  InstanceTeardownStart
	NULL,                               //  InstanceTeardownComplete
	NULL                                //  GenerateFileName
};

NTSTATUS FilterInitialize(PDRIVER_OBJECT DriverObject, PanoptesState* State) {
	FilterHandle = State->FilterHandle;

	NTSTATUS status = FltRegisterFilter(DriverObject, &FilterRegistration, &State->FilterHandle);
	if (!NT_SUCCESS(status)) {
		switch (status)
		{
		case STATUS_INSUFFICIENT_RESOURCES:
			KdPrint((PANOPTES_PREFIX_ERROR "Filter Registration Error:STATUS_INSUFFICIENT_RESOURCES\n"));
			break;
		case STATUS_INVALID_PARAMETER:
			KdPrint((PANOPTES_PREFIX_ERROR "Filter Registration Error: STATUS_INVALID_PARAMETER\n"));
			break;
		case STATUS_FLT_NOT_INITIALIZED:
			KdPrint((PANOPTES_PREFIX_ERROR "Filter Registration Error: STATUS_FLT_NOT_INITIALIZED\n"));
			break;
		case STATUS_OBJECT_NAME_NOT_FOUND:
			KdPrint((PANOPTES_PREFIX_ERROR "Filter Registration Error: STATUS_OBJECT_NAME_NOT_FOUND\n"));
			break;
		default:
			KdPrint((PANOPTES_PREFIX_ERROR "Filter Registration Error: UNKNOWN\n"));
			break;
		}
		return status;
	}

	status = FltStartFiltering(State->FilterHandle);
	if (!NT_SUCCESS(status)) {
		KdPrint((PANOPTES_PREFIX_ERROR "Failed to start filtering\n"));
		FltUnregisterFilter(State->FilterHandle);
		State->FilterHandle = nullptr;
		return status;
	}

	return status;
}

NTSTATUS GetFileInfo(PFLT_CALLBACK_DATA Data, PUNICODE_STRING* OutFileName) {
	PFLT_FILE_NAME_INFORMATION fileNameInfo = NULL;
	NTSTATUS status = FltGetFileNameInformation(Data,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY | FLT_FILE_NAME_DO_NOT_CACHE,
		&fileNameInfo);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	SIZE_T totalSize = sizeof(UNICODE_STRING) + fileNameInfo->Name.Length + sizeof(WCHAR);
	PUNICODE_STRING result = (PUNICODE_STRING)ExAllocatePoolWithTag(PagedPool, totalSize, DRIVER_TAG);
	if (!result) {
		FltReleaseFileNameInformation(fileNameInfo);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	result->Buffer = (PWCH)(result + 1);
	result->Length = fileNameInfo->Name.Length;
	result->MaximumLength = fileNameInfo->Name.Length + sizeof(WCHAR);

	RtlCopyMemory(result->Buffer, fileNameInfo->Name.Buffer, fileNameInfo->Name.Length);
	result->Buffer[fileNameInfo->Name.Length / sizeof(WCHAR)] = L'\0';

	*OutFileName = result;
	FltReleaseFileNameInformation(fileNameInfo);
	return STATUS_SUCCESS;
}

void MailSlotStatus(PFLT_CALLBACK_DATA Data) {
	PFLT_FILE_NAME_INFORMATION fileNameInfo = NULL;
	NTSTATUS status = FltGetFileNameInformation(Data,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY | FLT_FILE_NAME_DO_NOT_CACHE,
		&fileNameInfo);
	if (!NT_SUCCESS(status)) {
		return;
	}

	HANDLE sourceProcessId = PsGetCurrentProcessId();
	HANDLE sourceThreadId = PsGetThreadId(Data->Thread);

	switch (Data->IoStatus.Information)
	{
	case FILE_CREATED:
		Log_MailSlotCreate(sourceProcessId, sourceThreadId, fileNameInfo->Name.Buffer);
		break;
	case FILE_OPENED:
		Log_MailSlotOpen(sourceProcessId, sourceThreadId, fileNameInfo->Name.Buffer);
		break;
	}

	FltReleaseFileNameInformation(fileNameInfo);
}

void NamedPipeStatus(PFLT_CALLBACK_DATA Data) {
	PFLT_FILE_NAME_INFORMATION fileNameInfo = NULL;
	NTSTATUS status = FltGetFileNameInformation(Data,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY | FLT_FILE_NAME_DO_NOT_CACHE,
		&fileNameInfo);
	if (!NT_SUCCESS(status)) {
		return;
	}

	HANDLE sourceProcessId = PsGetCurrentProcessId();
	HANDLE sourceThreadId = PsGetThreadId(Data->Thread);

	switch (Data->IoStatus.Information)
	{
	case FILE_CREATED:
		Log_NamedPipeCreate(sourceProcessId, sourceThreadId, fileNameInfo->Name.Buffer);
		break;
	case FILE_OPENED:
		Log_NamedPipeOpen(sourceProcessId, sourceThreadId, fileNameInfo->Name.Buffer);
		break;
	}

	FltReleaseFileNameInformation(fileNameInfo);
}

void FileWriteStatus(PFLT_CALLBACK_DATA Data) {
	PFLT_FILE_NAME_INFORMATION fileNameInfo = NULL;
	NTSTATUS status = FltGetFileNameInformation(Data,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY | FLT_FILE_NAME_DO_NOT_CACHE,
		&fileNameInfo);
	if (!NT_SUCCESS(status)) {
		return;
	}

	HANDLE sourceProcessId = PsGetCurrentProcessId();
	HANDLE sourceThreadId = PsGetThreadId(Data->Thread);
	ULONG writeLength = Data->Iopb->Parameters.Write.Length;
	LARGE_INTEGER fileOffset = Data->Iopb->Parameters.Write.ByteOffset;

	switch (Data->Iopb->MinorFunction)
	{
	case IRP_MN_NORMAL:
		Log_FileWrite(sourceProcessId, sourceThreadId, fileNameInfo->Name.Buffer, fileOffset, writeLength, FALSE);
		break;
	case IRP_MN_COMPRESSED:
		Log_FileWrite(sourceProcessId, sourceThreadId, fileNameInfo->Name.Buffer, fileOffset, writeLength, TRUE);
		break;
	}

	FltReleaseFileNameInformation(fileNameInfo);
}

void FileReadStatus(PFLT_CALLBACK_DATA Data) {
	PFLT_FILE_NAME_INFORMATION fileNameInfo = NULL;
	NTSTATUS status = FltGetFileNameInformation(Data,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY | FLT_FILE_NAME_DO_NOT_CACHE,
		&fileNameInfo);
	if (!NT_SUCCESS(status)) {
		return;
	}

	HANDLE sourceProcessId = PsGetCurrentProcessId();
	HANDLE sourceThreadId = PsGetThreadId(Data->Thread);
	ULONG readLength = Data->Iopb->Parameters.Read.Length;
	LARGE_INTEGER fileOffset = Data->Iopb->Parameters.Read.ByteOffset;

	switch (Data->Iopb->MinorFunction)
	{
	case IRP_MN_NORMAL:
		Log_FileRead(sourceProcessId, sourceThreadId, fileNameInfo->Name.Buffer, fileOffset, readLength, FALSE);
		break;
	case IRP_MN_COMPRESSED:
		Log_FileRead(sourceProcessId, sourceThreadId, fileNameInfo->Name.Buffer, fileOffset, readLength, TRUE);
		break;
	}

	FltReleaseFileNameInformation(fileNameInfo);
}

BOOLEAN FilterNoise(UNICODE_STRING filePath, HANDLE SourceProcess) {
	PEPROCESS targetProcess = NULL;
	PUNICODE_STRING processPath = NULL;
	BOOLEAN result = FALSE;

	NTSTATUS status = PsLookupProcessByProcessId(SourceProcess, &targetProcess);
	if (!NT_SUCCESS(status)) {
		goto FileCheck;
	}

	status = SeLocateProcessImageName(targetProcess, &processPath);
	if (!NT_SUCCESS(status)) {
		goto Cleanup;
	}

	UNICODE_STRING proc1;
	RtlInitUnicodeString(&proc1, L"VMware");
	if (RtlCompareUnicodeString(&proc1, processPath, TRUE) == 0) {
		result = TRUE;
		goto Cleanup;
	}

Cleanup:
	if (processPath) {
		ExFreePool(processPath);
	}
	if (targetProcess) {
		ObDereferenceObject(targetProcess); 
	}

FileCheck:

	//"\Device\HarddiskVolume3\Program Files\VMware\VMware Tools\plugins\vmusr\vmtray.dll"
	UNICODE_STRING ignore1;
	RtlInitUnicodeString(&ignore1, L"\\ProgramData\\VMware\\");
	UNICODE_STRING ignore2;
	RtlInitUnicodeString(&ignore2, L"\\Device\\HarddiskVolume1\\");
	UNICODE_STRING ignore3;
	RtlInitUnicodeString(&ignore3, L"\\Device\\HarddiskVolume3\\");
	UNICODE_STRING ignore4;
	RtlInitUnicodeString(&ignore4, L"\\pagefile.sys");
	UNICODE_STRING ignore5;
	RtlInitUnicodeString(&ignore5, L"\\Device\\HarddiskVolume3\\Windows\\System32\\");
	UNICODE_STRING ignore6;
	RtlInitUnicodeString(&ignore6, L"\\Windows\\System32\\");

	if (RtlPrefixUnicodeString(&ignore1, &filePath, TRUE) || 
		RtlEqualUnicodeString(&ignore2, &filePath, TRUE) ||
		RtlEqualUnicodeString(&ignore3, &filePath, TRUE) ||
		RtlEqualUnicodeString(&ignore4, &filePath, TRUE) ||
		RtlPrefixUnicodeString(&ignore5, &filePath, TRUE) ||
		RtlPrefixUnicodeString(&ignore6, &filePath, TRUE) 
	)
	{
		return true;
	}

	return false;
}

void FileCreationStatus(PFLT_CALLBACK_DATA Data) {
	PFLT_FILE_NAME_INFORMATION fileNameInfo = NULL;
	NTSTATUS status = FltGetFileNameInformation(Data,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY | FLT_FILE_NAME_DO_NOT_CACHE,
		&fileNameInfo);
	if (!NT_SUCCESS(status)) {
		return;
	}

	HANDLE sourceProcessId = PsGetCurrentProcessId();
	HANDLE sourceThreadId = PsGetThreadId(Data->Thread);
	
	if (FilterNoise(fileNameInfo->Name, sourceProcessId)) {
		FltReleaseFileNameInformation(fileNameInfo);
		return;
	}

	BOOLEAN completeIfOplocked = (Data->Iopb->Parameters.Create.Options & FILE_COMPLETE_IF_OPLOCKED) != 0;;


	switch (Data->IoStatus.Information) {
	case FILE_CREATED:
		Log_FileCreated(sourceProcessId, sourceThreadId, fileNameInfo->Name.Buffer, completeIfOplocked);
		break;
	case FILE_OPENED:
		Log_FileOpen(sourceProcessId, sourceThreadId, fileNameInfo->Name.Buffer, completeIfOplocked);
		break;
	case FILE_OVERWRITTEN:
		Log_FileOverwritten(sourceProcessId, sourceThreadId, fileNameInfo->Name.Buffer);
		break;
	case FILE_SUPERSEDED:
		Log_FileSuperseded(sourceProcessId, sourceThreadId, fileNameInfo->Name.Buffer);
		break;
	}

	FltReleaseFileNameInformation(fileNameInfo);
}

FLT_POSTOP_CALLBACK_STATUS PostOperationCallback(PFLT_CALLBACK_DATA Data,PCFLT_RELATED_OBJECTS FltObjects,PVOID CompletionContext,FLT_POST_OPERATION_FLAGS Flags) {
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	switch (Data->Iopb->MajorFunction)
	{
		//https://learn.microsoft.com/en-us/previous-versions/windows/drivers/ifs/irp-mj-read
	case IRP_MJ_READ:
		FileReadStatus(Data);
		break;
		//https://learn.microsoft.com/en-us/previous-versions/windows/drivers/ifs/irp-mj-create
	case IRP_MJ_CREATE:
		FileCreationStatus(Data);
		break;
		//https://learn.microsoft.com/en-us/previous-versions/windows/drivers/ifs/irp-mj-write
	case IRP_MJ_WRITE:
		FileWriteStatus(Data);
		break;
		//https://learn.microsoft.com/en-us/previous-versions/windows/drivers/ifs/irp-mj-create-named-pipe
	case IRP_MJ_CREATE_NAMED_PIPE:
		NamedPipeStatus(Data);
		break;
		//https://learn.microsoft.com/en-us/previous-versions/windows/drivers/ifs/irp-mj-create-mailslot
	case IRP_MJ_CREATE_MAILSLOT:
		MailSlotStatus(Data);
		break;
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}


