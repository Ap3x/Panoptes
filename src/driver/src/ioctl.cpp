#include "ioctl.h"

//NTSTATUS DeviceCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
//{
//	PAGED_CODE();
//	UNREFERENCED_PARAMETER(DeviceObject);
//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Driver - DeviceCreate\n");
//
//	Irp->IoStatus.Status = STATUS_SUCCESS;
//	Irp->IoStatus.Information = 0;
//	IoCompleteRequest(Irp, IO_NO_INCREMENT);
//
//	return STATUS_SUCCESS;
//}
 
//NTSTATUS DeviceClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
//{
//	PAGED_CODE();
//	UNREFERENCED_PARAMETER(DeviceObject);
//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Driver - DeviceClose\n");
//
//	Irp->IoStatus.Status = STATUS_SUCCESS;
//	Irp->IoStatus.Information = 0;
//	IoCompleteRequest(Irp, IO_NO_INCREMENT);
//
//	return STATUS_SUCCESS;
//}

//NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
//{
//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: HERE6\n");
//
//	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
//	NTSTATUS status = STATUS_SUCCESS;
//	ULONG_PTR bytesTransferred = 0;
//	ULONG inputBufferLength = 0;
//	EVENT_DATA eventData;
//	RtlZeroMemory(&eventData, sizeof(EVENT_DATA));
//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: BEFORE\n");
//
//
//	switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
//	case IOCTL_GET_EVENT:
//	{
//		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Control Process Code Read\n");
//
//		if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(EVENT_DATA))
//		{
//			status = STATUS_BUFFER_TOO_SMALL;
//			break;
//		}
//
//		if (DequeueEvent(&eventData))
//		{
//			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Driver - Dequeued %wd Type Successfully\n", eventData.Type);
//
//			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Dequeued an event\n");
//			if (eventData.Type == EVENT_TYPE_PROCESS_CREATE) {
//				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Sending Parent PID %llu\n", eventData.Data.ProcessData.ParentProcessId);
//				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Sending main PID %llu\n", eventData.Data.ProcessData.ProcessId);
//			}
//			else if (eventData.Type == EVENT_TYPE_IMAGE_LOAD) {
//				//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Sending %wZ\n", &eventData.Data.ImageLoadData);
//				//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Sending Parent PID %llu\n", eventData.Data.ProcessData.ParentProcessId);
//				//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Sending main PID %llu\n", eventData.Data.ProcessData.ProcessId);
//			}
//
//			RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &eventData, sizeof(EVENT_DATA));
//			bytesTransferred = sizeof(EVENT_DATA);
//			status = STATUS_SUCCESS;
//
//		}
//		else
//		{
//			// No event available, handle accordingly (e.g., wait or return status)
//			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Panoptes: NO MORE ENTRIES\n");
//			status = STATUS_NO_MORE_ENTRIES;
//		}
//		break;
//	}
//	case IOCTL_TERMINATE_PROCESS:
//	{
//		inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
//		if (inputBufferLength < sizeof(TERMINATE_PROCESS))
//		{
//			status = STATUS_BUFFER_TOO_SMALL;
//			break;
//		}
//
//		PTERMINATE_PROCESS inputBuffer = (PTERMINATE_PROCESS)Irp->AssociatedIrp.SystemBuffer;
//
//		HANDLE processHandle;
//		NTSTATUS status = GetProcessHandleFromPID(inputBuffer->ProcessId, &processHandle);
//
//		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: PID to terminate = % lu\n", inputBuffer->ProcessId);
//
//		ZwTerminateProcess(processHandle, STATUS_SUCCESS);
//
//		ZwClose(processHandle);
//		break;
//	}
//	default:
//		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Panoptes: INVALID REQUEST\n");
//		status = STATUS_INVALID_DEVICE_REQUEST;
//		break;
//	}
//
//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Complete IRP\n");
//
//	Irp->IoStatus.Information = bytesTransferred;
//	Irp->IoStatus.Status = status;
//	IoCompleteRequest(Irp, IO_NO_INCREMENT);
//
//	return status;
//}

//NTSTATUS InitializeDriverLink(PDRIVER_OBJECT driverObject) {
//	PAGED_CODE();
//	NTSTATUS status = STATUS_SUCCESS;
//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Initializing Driver Link\n");
//	//RtlInitUnicodeString(&g_deviceName, KERNEL_LINK);
//
//	driverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
//	driverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;
//	//driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
//
//	//status = IoCreateDevice(
//	//	driverObject,
//	//	0,
//	//	&g_deviceName,
//	//	FILE_DEVICE_UNKNOWN,
//	//	FILE_DEVICE_SECURE_OPEN,
//	//	FALSE,
//	//	&g_deviceObject
//	//);
//	//if (!NT_SUCCESS(status))
//	//{
//	//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Panoptes: An error occured when attempting to create the device object\n");
//	//	return status;
//	//}
//
//	//RtlInitUnicodeString(&g_symLink, KERNEL_LINK_SYM);
//	//status = IoCreateSymbolicLink(&g_symLink, &g_deviceName);
//	//if (!NT_SUCCESS(status))
//	//{
//	//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Panoptes: An error occured when attempting to create the device object symobolic link\n");
//	//	IoDeleteDevice(g_deviceObject);
//	//	return status;
//	//}
//
//
//	return status;
//}
