#include "structs.h"
#include "inject.h"

NTSTATUS WriteToTargetProcessMemory(PEPROCESS targetProcess, PVOID TargetAddress, SIZE_T Size, PVOID DataToWrite)
{
	KAPC_STATE apcState;
	PMDL mdl = NULL;
	PVOID kernelAddress = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	// Attach to the target process
	KeStackAttachProcess(targetProcess, &apcState);

	__try {
		// Create the MDL for the target process memory
		mdl = IoAllocateMdl(TargetAddress, (ULONG)Size, FALSE, FALSE, NULL);
		if (!mdl) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		__try {
			// Probe and lock the pages
			MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);

			// Map the MDL to system address space
			kernelAddress = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
			if (!kernelAddress) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				__leave;
			}

			// Write to the mapped address
			RtlCopyMemory(kernelAddress, DataToWrite, Size);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
		}
	}
	__finally {
		// Cleanup
		if (kernelAddress) {
			MmUnmapLockedPages(kernelAddress, mdl);
		}
		if (mdl) {
			if (mdl->MdlFlags & MDL_PAGES_LOCKED) {
				MmUnlockPages(mdl);
			}
			IoFreeMdl(mdl);
		}

		// Detach from the target process
		KeUnstackDetachProcess(&apcState);

		// Dereference the process
		ObDereferenceObject(targetProcess);
	}

	return status;
}

NTSTATUS AllocateMemoryInUserProcess(PEPROCESS targetProcess, SIZE_T Size, PVOID* AllocatedAddress)
{
	HANDLE processHandle = NULL;
	NTSTATUS status;
	SIZE_T allocSize = Size;
	PVOID baseAddress = NULL;

	// Open a handle to the process
	status = ObOpenObjectByPointer(targetProcess,
		OBJ_KERNEL_HANDLE,
		NULL,
		PROCESS_ALL_ACCESS,
		*PsProcessType,
		KernelMode,
		&processHandle);

	if (NT_SUCCESS(status)) {
		// Allocate memory in the target process
		status = ZwAllocateVirtualMemory(processHandle,
			&baseAddress,
			0,
			&allocSize,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);

		if (NT_SUCCESS(status)) {
			//RtlZeroMemory(baseAddress, Size);
			*AllocatedAddress = baseAddress;
		}

		// Close the process handle
		ZwClose(processHandle);
	}

	// Dereference the process
	ObDereferenceObject(targetProcess);

	return status;
}