#include "pano_filter.h"
#include "trace.h"

PFLT_FILTER g_FilterHandle;

PWCH GetFileInfo(
	PFLT_CALLBACK_DATA Data
) 
{
	PFLT_FILE_NAME_INFORMATION fileNameInfo = NULL;
	NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY | FLT_FILE_NAME_DO_NOT_CACHE, &fileNameInfo);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Error getting file info\n");
	}

	if (fileNameInfo == NULL) {
		return Data->Iopb->TargetFileObject->FileName.Buffer;
	}
	else {
		return fileNameInfo->Name.Buffer;
	}
}

void MailSlotStatus(
	PFLT_CALLBACK_DATA Data
)
{
	PWCH fileName = GetFileInfo(Data);
	HANDLE sourceProcessId = PsGetCurrentProcessId();
	HANDLE sourceThreadId = PsGetThreadId(Data->Thread);

	switch (Data->IoStatus.Information)
	{
	case FILE_CREATED:
		Log_MailSlotCreate(sourceProcessId, sourceThreadId, fileName);
		break;
	case FILE_OPENED:
		Log_MailSlotOpen(sourceProcessId, sourceThreadId, fileName);
		break;
	}
}

void NamedPipeStatus(
	PFLT_CALLBACK_DATA Data
)
{
	PWCH fileName = GetFileInfo(Data);
	HANDLE sourceProcessId = PsGetCurrentProcessId();
	HANDLE sourceThreadId = PsGetThreadId(Data->Thread);

	switch (Data->IoStatus.Information)
	{
	case FILE_CREATED:
		Log_NamedPipeCreate(sourceProcessId, sourceThreadId, fileName);
		break;
	case FILE_OPENED:
		Log_NamedPipeOpen(sourceProcessId, sourceThreadId, fileName);
		break;
	}
}

void FileWriteStatus(
	PFLT_CALLBACK_DATA Data
)
{
	PWCH fileName = GetFileInfo(Data);
	HANDLE sourceProcessId = PsGetCurrentProcessId();
	HANDLE sourceThreadId = PsGetThreadId(Data->Thread);
	ULONG writeLength = Data->Iopb->Parameters.Write.Length;
	LARGE_INTEGER fileOffset = Data->Iopb->Parameters.Write.ByteOffset;

	switch (Data->Iopb->MinorFunction)
	{
	case IRP_MN_NORMAL:
		Log_FileWrite(sourceProcessId, sourceThreadId, fileName, fileOffset, writeLength, FALSE);
		break;
	case IRP_MN_COMPRESSED:
		Log_FileWrite(sourceProcessId, sourceThreadId, fileName, fileOffset, writeLength, TRUE);
		break;
	}
}

void FileReadStatus(
	PFLT_CALLBACK_DATA Data
)
{
	PWCH fileName = GetFileInfo(Data);

	HANDLE sourceProcessId = PsGetCurrentProcessId();
	HANDLE sourceThreadId = PsGetThreadId(Data->Thread);
	ULONG readLength = Data->Iopb->Parameters.Read.Length;
	LARGE_INTEGER fileOffset = Data->Iopb->Parameters.Read.ByteOffset;

	switch (Data->Iopb->MinorFunction)
	{
	case IRP_MN_NORMAL:
		Log_FileRead(sourceProcessId, sourceThreadId, fileName, fileOffset, readLength, FALSE);
		break;
	case IRP_MN_COMPRESSED:
		Log_FileRead(sourceProcessId, sourceThreadId, fileName, fileOffset, readLength, TRUE);
		break;
	}
}

void FileCreationStatus(
	PFLT_CALLBACK_DATA Data
) 
{
	PWCH fileName = GetFileInfo(Data);

	HANDLE sourceProcessId = PsGetCurrentProcessId();
	HANDLE sourceThreadId = PsGetThreadId(Data->Thread);
	//ULONG createOptions = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;
	//ULONG disposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
	//LONG status = Data->IoStatus.Status;

	BOOLEAN completeIfOplocked = (Data->Iopb->Parameters.Create.Options & FILE_COMPLETE_IF_OPLOCKED) != 0;;

	switch (Data->IoStatus.Information) {
	case FILE_CREATED:
		Log_FileCreated(sourceProcessId, sourceThreadId, fileName, completeIfOplocked);
		break;
	case FILE_OPENED:
		Log_FileOpen(sourceProcessId, sourceThreadId, fileName, completeIfOplocked);
		break;
	case FILE_OVERWRITTEN:
		Log_FileOverwritten(sourceProcessId, sourceThreadId, fileName);
		break;
	case FILE_SUPERSEDED:
		Log_FileSuperseded(sourceProcessId, sourceThreadId, fileName);
		break;
	}
}

FLT_POSTOP_CALLBACK_STATUS PostOperationCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	switch (Data->Iopb->MajorFunction)
	{
		//https://learn.microsoft.com/en-us/previous-versions/windows/drivers/ifs/irp-mj-read
	case IRP_MJ_READ:
		DbgPrint("IRP_MJ_READ\n");
		FileReadStatus(Data);
		break;
		//https://learn.microsoft.com/en-us/previous-versions/windows/drivers/ifs/irp-mj-create
	case IRP_MJ_CREATE:
		DbgPrint("IRP_MJ_CREATE\n");
		FileCreationStatus(Data);
		break;
		//https://learn.microsoft.com/en-us/previous-versions/windows/drivers/ifs/irp-mj-write
	case IRP_MJ_WRITE:
		DbgPrint("IRP_MJ_WRITE\n");
		FileWriteStatus(Data);
		break;
		//https://learn.microsoft.com/en-us/previous-versions/windows/drivers/ifs/irp-mj-create-named-pipe
	case IRP_MJ_CREATE_NAMED_PIPE:
		DbgPrint("IRP_MJ_CREATE_NAMED_PIPE\n");
		NamedPipeStatus(Data);
		break;
		//https://learn.microsoft.com/en-us/previous-versions/windows/drivers/ifs/irp-mj-create-mailslot
	case IRP_MJ_CREATE_MAILSLOT:
		DbgPrint("IRP_MJ_CREATE_MAILSLOT\n");
		MailSlotStatus(Data);
		break;
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS PanoptesFilterUnload
(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
	PAGED_CODE();
	NTSTATUS status;
	if (Flags == FLTFL_FILTER_UNLOAD_MANDATORY) {
		FltUnregisterFilter(g_FilterHandle);
		status = STATUS_SUCCESS;
	}
	else {
		status = STATUS_FLT_DO_NOT_DETACH;
	}
	return status;
}

#pragma region FilterRegistration

const FLT_OPERATION_REGISTRATION Callbacks[] = {

	{ IRP_MJ_CREATE,
	  0,
	  NULL,
	  PostOperationCallback
	},
	{
	  IRP_MJ_READ,
	  0,
	  NULL,
	  PostOperationCallback
	},
	{ IRP_MJ_WRITE,
	  0,
	  NULL,
	  PostOperationCallback
	},
	{ IRP_MJ_CREATE_NAMED_PIPE,
	  0,
	  NULL,
	  PostOperationCallback
	},
	{
	  IRP_MJ_CREATE_MAILSLOT,
	  0,
	  NULL,
	  PostOperationCallback
	},
	{ IRP_MJ_OPERATION_END}
};

const FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags
	NULL,						//  Context Registration.
	Callbacks,                          //  Operation callbacks
	PanoptesFilterUnload,                      //  FilterUnload
	NULL,                               //  InstanceSetup
	NULL,                               //  InstanceQueryTeardown
	NULL,                               //  InstanceTeardownStart
	NULL,                               //  InstanceTeardownComplete
	NULL                                //  GenerateFileName
};

#pragma endregion

NTSTATUS FilterInit(PDRIVER_OBJECT* DriverObject)
{
	NTSTATUS status = FltRegisterFilter(
		*DriverObject,                  //Driver
		&FilterRegistration,           //Registration
		&g_FilterHandle);               //RetFilter
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed FltRegisterFilter\n");
		switch (status)
		{
		case STATUS_INSUFFICIENT_RESOURCES:
			DbgPrint("STATUS_INSUFFICIENT_RESOURCES\n");
			break;
		case STATUS_INVALID_PARAMETER:
			DbgPrint("STATUS_INVALID_PARAMETER\n");
			break;
		case STATUS_FLT_NOT_INITIALIZED:
			DbgPrint("STATUS_FLT_NOT_INITIALIZED\n");
			break;
		case STATUS_OBJECT_NAME_NOT_FOUND:
			DbgPrint("STATUS_OBJECT_NAME_NOT_FOUND\n");
			break;
		default:
			DbgPrint("UNKNOWN\n");
			break;
		}
		return status;
	}

	status = FltStartFiltering(g_FilterHandle);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed FltStartFiltering\n");
		FltUnregisterFilter(g_FilterHandle);
		g_FilterHandle = nullptr;
		return status;
	}

	return status;
}
