#include "ioctl.h"
#include "event_queue.h"
#include "inject_exclusions.h"
#include "pano_filter.h"
#include <wdmsec.h>

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif

static PDEVICE_OBJECT g_DeviceObject;
static UNICODE_STRING g_SymbolicLink = RTL_CONSTANT_STRING(PANOPTES_SYMLINK_NAME);

static NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS Status)
{
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

static NTSTATUS TerminateProcessById(UINT64 ProcessId)
{
	// Refuse the idle and system processes
	if (ProcessId <= 4) {
		return STATUS_ACCESS_DENIED;
	}

	PEPROCESS process;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	HANDLE processHandle;
	status = ObOpenObjectByPointer(
		process,
		OBJ_KERNEL_HANDLE,
		NULL,
		PROCESS_TERMINATE,
		*PsProcessType,
		KernelMode,
		&processHandle);
	ObDereferenceObject(process);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = ZwTerminateProcess(processHandle, STATUS_SUCCESS);
	ZwClose(processHandle);
	return status;
}

static NTSTATUS DeviceCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	return CompleteRequest(Irp, STATUS_SUCCESS);
}

// IRP_MJ_CLEANUP (the last handle to a file object was closed) and IRP_MJ_CLOSE
// (its last reference went away). Either may end an event consumer
static NTSTATUS DeviceCleanupClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	EventQueueCleanupFile(IoGetCurrentIrpStackLocation(Irp)->FileObject);
	return CompleteRequest(Irp, STATUS_SUCCESS);
}

static NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status;

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_PANOPTES_TERMINATE_PROCESS:
	{
		if (irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(PANO_TERMINATE_PROCESS)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		PPANO_TERMINATE_PROCESS request = (PPANO_TERMINATE_PROCESS)Irp->AssociatedIrp.SystemBuffer;
		status = TerminateProcessById(request->ProcessId);
		if (!NT_SUCCESS(status)) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Panoptes: Failed to terminate PID %llu with status 0x%X\n", request->ProcessId, status);
		}
		break;
	}
	case IOCTL_PANOPTES_SET_INJECTION_EXCLUSIONS:
	{
		status = InjectExclusionsSet(Irp->AssociatedIrp.SystemBuffer, irpSp->Parameters.DeviceIoControl.InputBufferLength);
		if (!NT_SUCCESS(status)) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Panoptes: Failed to set the injection exclusion list with status 0x%X\n", status);
		}
		break;
	}
	case IOCTL_PANOPTES_SET_FILE_EVENTS:
	{
		status = FilterSetFileEvents(Irp->AssociatedIrp.SystemBuffer, irpSp->Parameters.DeviceIoControl.InputBufferLength);
		if (!NT_SUCCESS(status)) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Panoptes: Failed to set the file event groups with status 0x%X\n", status);
		}
		break;
	}
	case IOCTL_PANOPTES_GET_EVENT:
	{
		// Inverted call: the queue either completes the request now (an event was
		// waiting) or parks it pending until an event fires. Either way it owns
		// the IRP from here, so we must not complete it ourselves.
		if (EventQueueReceiveRequest(Irp, &status)) {
			return status;
		}
		break;
	}
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	return CompleteRequest(Irp, status);
}

NTSTATUS InitializeDriverLink(PDRIVER_OBJECT DriverObject)
{
	PAGED_CODE();
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(PANOPTES_DEVICE_NAME);

	// Only SYSTEM and Administrators may open the device
	NTSTATUS status = IoCreateDeviceSecure(
		DriverObject,
		0,
		&deviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
		NULL,
		&g_DeviceObject);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Panoptes: Failed to create the device object with status 0x%X\n", status);
		return status;
	}

	status = IoCreateSymbolicLink(&g_SymbolicLink, &deviceName);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Panoptes: Failed to create the device symbolic link with status 0x%X\n", status);
		IoDeleteDevice(g_DeviceObject);
		g_DeviceObject = NULL;
		return status;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = DeviceCleanupClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceCleanupClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;

	return STATUS_SUCCESS;
}

void RemoveDriverLink()
{
	PAGED_CODE();
	if (g_DeviceObject == NULL) {
		return;
	}

	IoDeleteSymbolicLink(&g_SymbolicLink);
	IoDeleteDevice(g_DeviceObject);
	g_DeviceObject = NULL;
}
