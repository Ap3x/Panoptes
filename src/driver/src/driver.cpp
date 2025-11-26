#include "pch.h"
#include "callbacks.h"
#include "trace.h"
#include "filter.h"
#include "state.h"

UNICODE_STRING g_deviceName;
UNICODE_STRING g_symLink;
PDEVICE_OBJECT g_deviceObject;
UNICODE_STRING g_SymbolicLinkName;

void UnloadPanoptes(PDRIVER_OBJECT DriverObject) {
	PAGED_CODE();
	KdPrint(( PANOPTES_PREFIX_SUCCESS "Driver Exit\n"));
	Log_DriverExit(DriverObject);
	//IoDeleteDevice(driver_object);
	//IoDeleteSymbolicLink(&g_symLink);
	RemoveCallbacks();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT  DriverObject,PUNICODE_STRING RegistryPath) {
	PAGED_CODE();
	DriverObject->DriverUnload = UnloadPanoptes;

	TraceInitialize();

	Log_DriverEntry(DriverObject, RegistryPath);

	NTSTATUS status = FilterInit(&DriverObject);
	if (!NT_SUCCESS(status)) {
		KdPrint(( PANOPTES_PREFIX_ERROR "An error occured when attempting to initialized filter\n"));
		return status;
	}

	//status = InitializeDriverLink(driver_object);
	//if (!NT_SUCCESS(status))
	//{
	//	KdPrint(( PANOPTES_PREFIX_ERROR "An error occured when attempting to initialized device pipe\n"));
	//	return status;
	//}

	NTSTATUS status = InitializeKernelCallbacks();
	if (!NT_SUCCESS(status))
	{
		KdPrint(( PANOPTES_PREFIX_ERROR "An error occured when attempting to initialized kernel callbacks\n"));
		return status;
	}

	return 0;
}
