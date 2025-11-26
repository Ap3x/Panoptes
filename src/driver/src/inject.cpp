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
	UNREFERENCED_PARAMETER(SystemArgument2);

	if (NormalContext == nullptr) {
		KdPrint(("InjectDll - processId is null"));
		return;
	}

	ULONG processId = HandleToUlong(NormalContext);

	PEPROCESS targetProcess{};
	NTSTATUS status = PsLookupProcessByProcessId(NormalContext, &targetProcess);
	if (!NT_SUCCESS(status)) {
		return;
	}

#ifdef _DEBUG
	PUNICODE_STRING processPath{};
	status = SeLocateProcessImageName(targetProcess, &processPath);
	if (!NT_SUCCESS(status)) {
		return;
	}

	UNICODE_STRING onlyProc{};
	RtlInitUnicodeString(&onlyProc, L"die.exe");
	if (wcsstr(processPath->Buffer, onlyProc.Buffer) == NULL) {
		return;
	}
#endif

	ANSI_STRING loadDllRoutineName = RTL_CONSTANT_STRING("LoadLibraryExW");
	PVOID testVal2 = SystemArgument1;
	PVOID testVal3 = *static_cast<PVOID*>(testVal2);
	PVOID functionAddress = RtlxFindExportedRoutineByName(testVal3, &loadDllRoutineName);
	if (functionAddress == nullptr) {
		KdPrint((PANOPTES_PREFIX_ERROR "Unable to find LoadLibraryExW in target process (%u)\n", processId));
		return;
	}

	UNICODE_STRING dllToInject;
	UNICODE_STRING dllFullPathx64;
	UNICODE_STRING dllFullPathx86;
	RtlInitUnicodeString(&dllFullPathx64, L"C:\\Program Files\\Panoptes\\PanoptesDLLx64.dll");
	RtlInitUnicodeString(&dllFullPathx86, L"C:\\Program Files\\Panoptes\\PanoptesDLLx86.dll");

	if (Is64BitProcess(targetProcess))
		dllToInject = dllFullPathx64;
	else
		dllToInject = dllFullPathx86;

	PVOID allocatedAddressContainingDllFullPath = nullptr;
	status = ZwAllocateVirtualMemory(NtCurrentProcess(), &allocatedAddressContainingDllFullPath, 0, (PSIZE_T)&dllToInject.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		KdPrint((PANOPTES_PREFIX_ERROR "Unable to allocate memory for the absolute DLL path in the target process (%u)\n", processId));
		return;
	}
	RtlCopyMemory(allocatedAddressContainingDllFullPath, dllToInject.Buffer, dllToInject.Length);

	PKAPC pKapc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), DRIVER_TAG);
	if (!pKapc) {
		KdPrint((PANOPTES_PREFIX_ERROR "Unable to allocate the KAPC object (%u)\n", processId));
		ZwFreeVirtualMemory(NtCurrentProcess(), &allocatedAddressContainingDllFullPath, (PSIZE_T)&dllToInject.Length, MEM_RELEASE);  // Free the allocated memory
		return;
	}

	KeInitializeApc(pKapc, KeGetCurrentThread(), OriginalApcEnvironment, KernelRundown, NULL, (PKNORMAL_ROUTINE)(functionAddress), UserMode, allocatedAddressContainingDllFullPath); // Initialize the APC
	if (!KeInsertQueueApc(pKapc, NULL, NULL, IO_NO_INCREMENT))
	{
		KdPrint((PANOPTES_PREFIX_ERROR "Unable to insert the KAPC object into target process(%u)\n", processId));
		ZwFreeVirtualMemory(NtCurrentProcess(), &allocatedAddressContainingDllFullPath, (PSIZE_T)&dllToInject.Length, MEM_RELEASE);  // Free the allocated memory
		ExFreePool(pKapc); // Free the APC object
		return;
	}

	KeTestAlertThread(UserMode);
}

NTSTATUS InstallKernelModeApcToInjectDll(HANDLE ProcessId, PVOID ImageBase)
{
	PRKAPC pKapc = nullptr;

	pKapc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), DRIVER_TAG); // Allocate the APC object
	if (nullptr == pKapc) {
		KdPrint((PANOPTES_PREFIX_ERROR "InstallKernelModeApcToInjectDll Failed to allocate memory for the APC"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KeInitializeApc(pKapc, KeGetCurrentThread(),OriginalApcEnvironment,KernelRundown, NULL,(PKNORMAL_ROUTINE)KernelAPCRoutine,KernelMode, (PVOID)ProcessId);
	if (!KeInsertQueueApc(pKapc, ImageBase, NULL, IO_NO_INCREMENT)) {
		KdPrint((PANOPTES_PREFIX_ERROR "InstallKernelModeApcToInjectDll Failed to insert APC"));
		ExFreePool(pKapc); // Free the APC object
		return STATUS_UNSUCCESSFUL;
	}
	else {
		KdPrint((PANOPTES_PREFIX_SUCCESS "InstallKernelModeApcToInjectDll APC delivered"));
	}

	return STATUS_SUCCESS;
}