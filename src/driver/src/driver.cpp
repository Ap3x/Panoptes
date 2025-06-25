#include "driver_constants.h"
#include "callbacks.h"
#include "pano_query.h"
#include "trace.h"
#include "pano_filter.h"

UNICODE_STRING g_deviceName;
UNICODE_STRING g_symLink;
PDEVICE_OBJECT g_deviceObject;
UNICODE_STRING g_SymbolicLinkName;

void UnloadPanoptes(PDRIVER_OBJECT DriverObject)
{
	PAGED_CODE();
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Driver Exit\n");
	Log_DriverExit(DriverObject);
	//IoDeleteDevice(driver_object);
	//IoDeleteSymbolicLink(&g_symLink);
	TraceUninit();
	RemoveCallbacks();
}

NTSTATUS DriverEntry(
	PDRIVER_OBJECT  DriverObject,
	PUNICODE_STRING RegistryPath
)
{
	PAGED_CODE();
	DriverObject->DriverUnload = UnloadPanoptes;

	TraceInit();
	Log_DriverEntry(DriverObject, RegistryPath);

	NTSTATUS status = FilterInit(&DriverObject);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Panoptes: An error occured when attempting to initialized filter\n");
		return status;
	}

	//status = InitializeDriverLink(driver_object);
	//if (!NT_SUCCESS(status))
	//{
	//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Panoptes: An error occured when attempting to initialized device pipe\n");
	//	return status;
	//}

	status = InitializeKernelCallbacks();
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Panoptes: An error occured when attempting to initialized kernel callbacks\n");
		return status;
	}

	return 0;
}
