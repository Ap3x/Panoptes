#include "inject.h"
#include "utils.h"

void NTAPI KernelRundown(PKAPC apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	ExFreePool(apc);
}

VOID KernelAPCRoutine(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	PUNICODE_STRING dllToInject = reinterpret_cast<PUNICODE_STRING>(SystemArgument2);

	if (dllToInject == nullptr) {
		return;
	}

	if (NormalContext == nullptr) {
		ExFreePool(dllToInject->Buffer);
		ExFreePool(dllToInject);
		return;
	}

	ULONG processId = HandleToUlong(NormalContext);

	PEPROCESS targetProcess{};
	NTSTATUS status = PsLookupProcessByProcessId(NormalContext, &targetProcess);
	if (!NT_SUCCESS(status)) {
		ExFreePool(dllToInject->Buffer);
		ExFreePool(dllToInject);
		return;
	}

#ifdef _DEBUG
	//PUNICODE_STRING processPath{};
	//status = SeLocateProcessImageName(targetProcess, &processPath);
	//if (!NT_SUCCESS(status)) {
	//	return;
	//}

	//UNICODE_STRING onlyProc{};
	//RtlInitUnicodeString(&onlyProc, L"die.exe");
	//if (wcsstr(processPath->Buffer, onlyProc.Buffer) == NULL) {
	//	return;
	//}
#endif

	PVOID rawImageBaseAddress = *static_cast<PVOID*>(SystemArgument1);
	PVOID functionAddress = RtlFindExportedRoutineByName(rawImageBaseAddress, "LoadLibraryExW");
	if (functionAddress == nullptr) {
		ExFreePool(dllToInject->Buffer);
		ExFreePool(dllToInject);
		return;
	}

	PVOID allocatedAddressContainingDllFullPath = nullptr;
	status = ZwAllocateVirtualMemory(NtCurrentProcess(), &allocatedAddressContainingDllFullPath, 0, (PSIZE_T)&dllToInject->Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		KdPrint((PANOPTES_PREFIX_ERROR "Unable to allocate memory for the absolute DLL path in the target process (%u)\n", processId));
		ExFreePool(dllToInject->Buffer);
		ExFreePool(dllToInject);
		return;
	}
	RtlCopyMemory(allocatedAddressContainingDllFullPath, dllToInject->Buffer, dllToInject->Length);

	PKAPC pKapc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), DRIVER_TAG);
	if (!pKapc) {
		KdPrint((PANOPTES_PREFIX_ERROR "Unable to allocate the KAPC object (%u)\n", processId));
		ZwFreeVirtualMemory(NtCurrentProcess(), &allocatedAddressContainingDllFullPath, (PSIZE_T)&dllToInject->Length, MEM_RELEASE);  // Free the allocated memory
		ExFreePool(dllToInject->Buffer);
		ExFreePool(dllToInject);
		return;
	}

	KeInitializeApc(pKapc, KeGetCurrentThread(), OriginalApcEnvironment, KernelRundown, NULL, (PKNORMAL_ROUTINE)(functionAddress), UserMode, allocatedAddressContainingDllFullPath); // Initialize the APC
	if (!KeInsertQueueApc(pKapc, NULL, NULL, IO_NO_INCREMENT))
	{
		KdPrint((PANOPTES_PREFIX_ERROR "Unable to insert the KAPC object into target process(%u)\n", processId));
		ZwFreeVirtualMemory(NtCurrentProcess(), &allocatedAddressContainingDllFullPath, (PSIZE_T)&dllToInject->Length, MEM_RELEASE);  // Free the allocated memory
		ExFreePool(pKapc); // Free the APC object
		ExFreePool(dllToInject->Buffer);
		ExFreePool(dllToInject);
		return;
	}

	KdPrint((PANOPTES_PREFIX_SUCCESS "Injecting into %u - %wZ \n", NormalContext));

	// Free the allocated DLL path memory - no longer needed after successful APC queue
	ExFreePool(dllToInject->Buffer);
	ExFreePool(dllToInject);

	KeTestAlertThread(UserMode);
}

NTSTATUS InstallKernelModeApcToInjectDll(HANDLE ProcessId, PVOID ImageBase, BOOLEAN is64Bit)
{
	PRKAPC pKapc = nullptr;
	PCWSTR dllPath = nullptr;
	SIZE_T dllPathLength = 0;

	// Select the appropriate DLL path
	dllPath = is64Bit
		? L"C:\\Program Files\\Panoptes\\PanoptesDLLx64.dll"
		: L"C:\\Program Files\\Panoptes\\PanoptesDLLx86.dll";
	dllPathLength = (wcslen(dllPath) + 1) * sizeof(WCHAR);

	// Allocate memory for the UNICODE_STRING structure
	PUNICODE_STRING pDllToInject = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), DRIVER_TAG);
	if (nullptr == pDllToInject) {
		KdPrint((PANOPTES_PREFIX_ERROR "InstallKernelModeApcToInjectDll Failed to allocate memory for UNICODE_STRING\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Allocate memory for the DLL path buffer
	PWCH pDllPathBuffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, dllPathLength, DRIVER_TAG);
	if (nullptr == pDllPathBuffer) {
		KdPrint((PANOPTES_PREFIX_ERROR "InstallKernelModeApcToInjectDll Failed to allocate memory for DLL path buffer\n"));
		ExFreePool(pDllToInject);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Copy the DLL path and initialize the UNICODE_STRING
	RtlCopyMemory(pDllPathBuffer, dllPath, dllPathLength);
	pDllToInject->Buffer = pDllPathBuffer;
	pDllToInject->Length = (USHORT)(dllPathLength - sizeof(WCHAR)); // Exclude null terminator
	pDllToInject->MaximumLength = (USHORT)dllPathLength;

	pKapc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), DRIVER_TAG); // Allocate the APC object
	if (nullptr == pKapc) {
		KdPrint((PANOPTES_PREFIX_ERROR "InstallKernelModeApcToInjectDll Failed to allocate memory for the APC\n"));
		ExFreePool(pDllPathBuffer);
		ExFreePool(pDllToInject);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KeInitializeApc(pKapc, KeGetCurrentThread(),OriginalApcEnvironment,KernelRundown, NULL,(PKNORMAL_ROUTINE)KernelAPCRoutine,KernelMode, (PVOID)ProcessId);
	if (!KeInsertQueueApc(pKapc, ImageBase, pDllToInject, IO_NO_INCREMENT)) {
		KdPrint((PANOPTES_PREFIX_ERROR "InstallKernelModeApcToInjectDll Failed to insert APC\n"));
		ExFreePool(pKapc); // Free the APC object
		ExFreePool(pDllPathBuffer);
		ExFreePool(pDllToInject);
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}