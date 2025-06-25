#include "structs.h"
#include "inject.h"

typedef NTSTATUS(NTAPI* PLDRLOADDLL)(
	PWCHAR PathToFile,
	ULONG Flags,
	PUNICODE_STRING ModuleFileName,
	PHANDLE ModuleHandle
	);

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

//void kernel_free_kapc(PKAPC apc, PKNORMAL_ROUTINE*, PVOID*, PVOID*, PVOID*)
//{
//	delete apc;
//	ExReleaseRundownProtection(&PendingOperations);
//
//}
//
//void rundown_free_kapc(PKAPC apc)
//{
//	delete apc;
//	ExReleaseRundownProtection(&PendingOperations);
//
//}

struct InjectArgs {
	PCWSTR DLLPath;
	PUNICODE_STRING DllName;
	PVOID* DllHandle;
};

//
//bool InjectDLL(HANDLE ProcessId, PVOID processInfo)
//{
//	PPANO_PROCESS_INFO panoProcessInfo = (PPANO_PROCESS_INFO)processInfo;
//	InjectArgs args;
//	args.DllHandle = NULL;
//	args.DLLPath = L"C:\\Program Files\\Panoptes";
//	PVOID allocatedAddressContainingShellcode;
//	PVOID shellcodeAddress;
//	// Get the EPROCESS pointer for the target process
//	PEPROCESS targetProcess = NULL;
//	NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &targetProcess);
//	if (!NT_SUCCESS(status)) {
//		return status;
//	}
//
//	if (panoProcessInfo->Is64Bit)
//	{
//		UNICODE_STRING moduleName;
//		RtlInitUnicodeString(&moduleName, L"PanoptesDLLx64.dll");
//		args.DllName = &moduleName;
//		SIZE_T dllPathx64Size = sizeof(_code_rawx64);
//		status = AllocateMemoryInUserProcess(targetProcess, dllPathx64Size, &allocatedAddressContainingShellcode);
//		if (!NT_SUCCESS(status)) {
//			return false;
//		}
//		status = WriteToTargetProcessMemory(targetProcess, &allocatedAddressContainingShellcode, dllPathx64Size, _code_rawx64);
//		shellcodeAddress = (PVOID)((UCHAR*)allocatedAddressContainingShellcode + FUNCTION_OFFSETx64);
//	}
//	else
//	{
//		UNICODE_STRING moduleName;
//		RtlInitUnicodeString(&moduleName, L"PanoptesDLLx86.dll");
//		args.DllName = &moduleName;
//		SIZE_T dllPathx86Size = sizeof(_code_rawx86);
//		status = AllocateMemoryInUserProcess(targetProcess, dllPathx86Size, &allocatedAddressContainingShellcode);
//		if (!NT_SUCCESS(status)) {
//			return false;
//		}
//		status = WriteToTargetProcessMemory(targetProcess, &allocatedAddressContainingShellcode, dllPathx86Size, _code_rawx86);
//		shellcodeAddress = (PVOID)((UCHAR*)allocatedAddressContainingShellcode + FUNCTION_OFFSETx86);
//	}
//
//	// Attach to the target process
//	KAPC_STATE ApcState;
//	KeStackAttachProcess(targetProcess, &ApcState);
//
//	KAPC* apc = static_cast<KAPC*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), 'ldll'));
//	if (nullptr == apc) {
//		return false;
//	}
//
//	DbgBreakPoint();
//
//	KeInitializeApc(
//		apc,
//		KeGetCurrentThread(),
//		OriginalApcEnvironment,
//		NULL,
//		NULL,
//		reinterpret_cast<PKNORMAL_ROUTINE>(shellcodeAddress),
//		UserMode,
//		&args
//		);
//
//	if (!KeInsertQueueApc(
//		apc,
//		NULL,
//		NULL,
//		IO_NO_INCREMENT
//	))
//	{
//		if (apc) {
//			ExFreePoolWithTag(apc, 0);
//		}
//		KeUnstackDetachProcess(&ApcState);
//		return false;
//	}
//
//	KeUnstackDetachProcess(&ApcState);
//	//panoProcessInfo->Injected = true;
//	return true;
//}
