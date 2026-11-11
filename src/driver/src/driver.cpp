#include "driver_constants.h"
#include "callbacks.h"
#include "ioctl.h"
#include "trace.h"
#include "pano_filter.h"
#include "event_queue.h"
#include "inject_exclusions.h"

void UnloadPanoptes(PDRIVER_OBJECT DriverObject)
{
	PAGED_CODE();
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Driver Exit\n");
	Log_DriverExit(DriverObject);
	RemoveCallbacks();
	FilterUninit();
	RemoveDriverLink();
	// Producers are stopped and the device is gone; drain any remaining requests/events.
	EventQueueCleanup();
	// The image load callback and the device are gone, so nothing reads or replaces the list
	InjectExclusionsCleanup();
	TraceUninit();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT  DriverObject,PUNICODE_STRING RegistryPath)
{
	PAGED_CODE();
	DriverObject->DriverUnload = UnloadPanoptes;

	TraceInit();
	// Before the device exists, since an IOCTL can replace the list as soon as it does. Every
	// DriverEntry failure path below runs before then, so none needs to free the list
	InjectExclusionsInit();

	NTSTATUS status = EventQueueInit();
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Panoptes: Failed to initialize the event queue\n");
		TraceUninit();
		return status;
	}

	status = FilterInit(&DriverObject);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Panoptes: An error occured when attempting to initialized filter\n");
		EventQueueCleanup();
		TraceUninit();
		return status;
	}

	status = InitializeDriverLink(DriverObject);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Panoptes: An error occured when attempting to initialize the driver link\n");
		FilterUninit();
		EventQueueCleanup();
		TraceUninit();
		return status;
	}

	status = InitializeKernelCallbacks();
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Panoptes: An error occured when attempting to initialized kernel callbacks\n");
		RemoveDriverLink();
		FilterUninit();
		EventQueueCleanup();
		TraceUninit();
		return status;
	}

	return STATUS_SUCCESS;
}
