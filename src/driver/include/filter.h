#pragma once
#include <fltKernel.h>
#include "state.h"

NTSTATUS FilterInitialize(PDRIVER_OBJECT DriverObject, PanoptesState* State);
FLT_POSTOP_CALLBACK_STATUS PostOperationCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags);
NTSTATUS FilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

const FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE,0,NULL,PostOperationCallback },
	{ IRP_MJ_READ, 0,NULL, PostOperationCallback },
	{ IRP_MJ_WRITE, 0, NULL, PostOperationCallback },
	{ IRP_MJ_CREATE_NAMED_PIPE, 0, NULL, PostOperationCallback},
	{ IRP_MJ_CREATE_MAILSLOT, 0, NULL, PostOperationCallback },
	{ IRP_MJ_OPERATION_END}
};

