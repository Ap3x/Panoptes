#include "callbacks.h"
#include "inject.h"
#include "driver_constants.h"
#include "pano_query.h"
#include <ntstrsafe.h>
#include "shellcode.h"


LIST_ENTRY g_ProcessList{};
KSPIN_LOCK g_ProcessListLock{};
PVOID g_ObRegistrationHandle{};

PVOID NTAPI RtlxFindExportedRoutineByName(_In_ PVOID DllBase,_In_ PANSI_STRING ExportName) {
	//
	// RtlFindExportedRoutineByName is not exported by ntoskrnl until Win10.
	// Following code is borrowed from ReactOS.
	//

	PULONG NameTable;
	PUSHORT OrdinalTable;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory;
	LONG Low = 0, Mid = 0, High, Ret;
	USHORT Ordinal;
	PVOID Function;
	ULONG ExportSize;
	PULONG ExportTable;

	//
	// Get the export directory.
	//

	ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(DllBase,
		TRUE,
		IMAGE_DIRECTORY_ENTRY_EXPORT,
		&ExportSize);

	if (!ExportDirectory)
	{
		return NULL;
	}

	//
	// Setup name tables.
	//

	NameTable = (PULONG)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNames);
	OrdinalTable = (PUSHORT)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNameOrdinals);

	//
	// Do a binary search.
	//

	High = ExportDirectory->NumberOfNames - 1;
	while (High >= Low)
	{
		//
		// Get new middle value.
		//

		Mid = (Low + High) >> 1;

		//
		// Compare name.
		//

		Ret = strcmp(ExportName->Buffer, (PCHAR)DllBase + NameTable[Mid]);
		if (Ret < 0)
		{
			//
			// Update high.
			//
			High = Mid - 1;
		}
		else if (Ret > 0)
		{
			//
			// Update low.
			//
			Low = Mid + 1;
		}
		else
		{
			//
			// We got it.
			//
			break;
		}
	}

	//
	// Check if we couldn't find it.
	//

	if (High < Low)
	{
		return NULL;
	}

	//
	// Otherwise, this is the ordinal.
	//

	Ordinal = OrdinalTable[Mid];

	//
	// Validate the ordinal.
	//

	if (Ordinal >= ExportDirectory->NumberOfFunctions)
	{
		return NULL;
	}

	//
	// Resolve the address and write it.
	//

	ExportTable = (PULONG)((ULONG_PTR)DllBase + ExportDirectory->AddressOfFunctions);
	Function = (PVOID)((ULONG_PTR)DllBase + ExportTable[Ordinal]);

	//
	// We found it!
	//

	NT_ASSERT(
		(Function < (PVOID)ExportDirectory) ||
		(Function > (PVOID)((ULONG_PTR)ExportDirectory + ExportSize))
	);

	return Function;
}

PPANO_PROCESS_INFO GetProcessInfo(HANDLE ProcessId)
{
	//KIRQL OldIRQL;
	//ExAcquireSpinLock(&g_ProcessListLock, &OldIRQL);
	PLIST_ENTRY entry = g_ProcessList.Flink;
	while (entry != &g_ProcessList) {
		PPANO_PROCESS_INFO processInfo = CONTAINING_RECORD(entry, PANO_PROCESS_INFO, ListEntry);
		if (processInfo->ProcessId == ProcessId) {
			return processInfo;
		}
		entry = entry->Flink;
	}
	//ExReleaseSpinLock(&g_ProcessListLock, NULL);
	return NULL;
}

VOID RemoveProcessInfo(HANDLE ProcessId)
{
	PLIST_ENTRY entry = g_ProcessList.Flink;
	while (entry != &g_ProcessList) {
		PPANO_PROCESS_INFO processInfo = CONTAINING_RECORD(entry, PANO_PROCESS_INFO, ListEntry);
		if (processInfo->ProcessId == ProcessId) {
			RemoveEntryList(entry);
			return;
		}
		entry = entry->Flink;
	}
	return;
}

void NTAPI KernelRoutine(PKAPC apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	ExFreePool(apc);
}

BOOLEAN CanInject(PPANO_PROCESS_INFO processInfo)
{
	if (processInfo->ntdllLoaded && processInfo->kernel32Loaded && processInfo->kernelBaseLoaded)
	{
		return TRUE;
	}
	return FALSE;
}

VOID InjectDllKernelApc(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	DbgPrint("InjectDll Entered");
	HANDLE pProcessId = (HANDLE)NormalContext;
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	if (nullptr == pProcessId)
	{
		DbgPrint("InjectDll - pProcessId is null");
	}

	PPANO_PROCESS_INFO pi = GetProcessInfo(pProcessId);
	ANSI_STRING loadDllRoutineName = RTL_CONSTANT_STRING("LoadLibraryExW");
	PVOID shellcodeAddress = RtlxFindExportedRoutineByName(pi->kernel32BaseAddress, &loadDllRoutineName);



	UNICODE_STRING dllToInject;
	UNICODE_STRING dllFullPathx64;
	UNICODE_STRING dllFullPathx86;
	RtlInitUnicodeString(&dllFullPathx64, L"C:\\Program Files\\Panoptes\\PanoptesDLLx64.dll");
	RtlInitUnicodeString(&dllFullPathx86, L"C:\\Program Files\\Panoptes\\PanoptesDLLx86.dll");
	PVOID allocatedAddressContainingDllFullPath = nullptr;

	if (pi->is64Bit)
	{
		dllToInject = dllFullPathx64;
	}
	else
	{
		dllToInject = dllFullPathx86;
	}

	NTSTATUS status = ZwAllocateVirtualMemory(NtCurrentProcess(), &allocatedAddressContainingDllFullPath, 0, (PSIZE_T)&dllToInject.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Error: Unable to allocate memory in the target process.");
		return;
	}
	RtlCopyMemory(allocatedAddressContainingDllFullPath, dllToInject.Buffer, dllToInject.Length);

	PKAPC pKapc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), 'tikt'); // Allocate the APC object
	if (!pKapc)
	{
		DbgPrint("Error: Unable to allocate the APC object.");
		ZwFreeVirtualMemory(NtCurrentProcess(), &allocatedAddressContainingDllFullPath, (PSIZE_T)&dllToInject.Length, MEM_RELEASE);  // Free the allocated memory
		return;
	}

	KeInitializeApc(pKapc, KeGetCurrentThread(), OriginalApcEnvironment, KernelRoutine, NULL, (PKNORMAL_ROUTINE)(shellcodeAddress), UserMode, allocatedAddressContainingDllFullPath); // Initialize the APC

	DbgPrint("Inserting APC to target thread");
	if (!KeInsertQueueApc(pKapc, NULL, NULL, IO_NO_INCREMENT))
	{
		DbgPrint("Error: Unable to insert APC to target thread.");
		ZwFreeVirtualMemory(NtCurrentProcess(), &allocatedAddressContainingDllFullPath, (PSIZE_T)&dllToInject.Length, MEM_RELEASE);  // Free the allocated memory
		ExFreePool(pKapc); // Free the APC object
		return;
	}

	KeTestAlertThread(UserMode);

	DbgPrint("InjectDllKernelApc exiting");
}

NTSTATUS InstallKernelModeApcToInjectDll(HANDLE ProcessId)
{
	PRKAPC pKapc = nullptr;
	PETHREAD pThread = nullptr;

	pKapc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), 'tiky'); // Allocate the APC object
	if (nullptr == pKapc)
	{
		DbgPrint("InstallKernelModeApcToInjectDll Failed to allocate memory for the APC");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	pThread = KeGetCurrentThread();
	KeInitializeApc(pKapc, pThread,
		OriginalApcEnvironment,
		KernelRoutine, NULL,
		(PKNORMAL_ROUTINE)InjectDllKernelApc,
		KernelMode, (PVOID)ProcessId);
	if (!KeInsertQueueApc(pKapc, NULL, NULL, IO_NO_INCREMENT))
	{
		DbgPrint("InstallKernelModeApcToInjectDll Failed to insert APC");
		ExFreePool(pKapc); // Free the APC object
		return STATUS_UNSUCCESSFUL;
	}
	else
	{
		DbgPrint("InstallKernelModeApcToInjectDll APC delivered");
	}

	return STATUS_SUCCESS;
}

BOOLEAN Is64BitProcess(PEPROCESS targetProcess) {
	UINT64* processAsUint64 = reinterpret_cast<UINT64*>(targetProcess);
	PVOID* wow64ProcessPtr = reinterpret_cast<PVOID*>(processAsUint64 + 0x580 / sizeof(UINT64));
	if (*wow64ProcessPtr == NULL)
	{
		return TRUE;
	}
	return FALSE;
}

VOID LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	PAGED_CODE();
	UNREFERENCED_PARAMETER(ImageInfo);

	PPANO_PROCESS_INFO processInfo = GetProcessInfo(ProcessId);
	if (!processInfo || processInfo->Injected)
	{
		return;
	}

	if (PsIsProtectedProcess(PsGetCurrentProcess()))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Panoptes: Skipping protected process %llu", (ULONG64)ProcessId);
		RemoveProcessInfo(ProcessId);
		return;
	}

	if (!CanInject(processInfo))
	{
		UNICODE_STRING ntdllLoadImage;
		RtlInitUnicodeString(&ntdllLoadImage, L"ntdll.dll");
		if (wcsstr(FullImageName->Buffer, ntdllLoadImage.Buffer) != NULL) {
			processInfo->ntdllLoaded = TRUE;
			return;
		}

		UNICODE_STRING kernel32LoadImage;
		RtlInitUnicodeString(&kernel32LoadImage, L"kernel32.dll");
		if (wcsstr(FullImageName->Buffer, kernel32LoadImage.Buffer) != NULL) {
			processInfo->kernel32Loaded = TRUE;
			processInfo->kernel32BaseAddress = ImageInfo->ImageBase;
			return;
		}

		UNICODE_STRING kernelbaseLoadImage;
		RtlInitUnicodeString(&kernelbaseLoadImage, L"KernelBase.dll");
		if (wcsstr(FullImageName->Buffer, kernelbaseLoadImage.Buffer) != NULL) {
			processInfo->kernelBaseLoaded = TRUE;
			return;
		}
	}
	else
	{
		PEPROCESS targetProcess = NULL;
		NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &targetProcess);
		if (!NT_SUCCESS(status)) {
			return;
		}

		PUNICODE_STRING processPath{};
		status = SeLocateProcessImageName(targetProcess, &processPath);
		if (!NT_SUCCESS(status)) {
			KdPrint((PANOPTES_PREFIX_WARNING "Failed to get process name, status: 0x%X\n", status));
			return;
		}

		processInfo->is64Bit = Is64BitProcess(targetProcess);
		if (processInfo->is64Bit) {
			KdPrint((PANOPTES_PREFIX_SUCCESS "Injecting into x64: (%llu) %wZ\n", (ULONG64)ProcessId, processPath));
		}
		else {
			KdPrint((PANOPTES_PREFIX_SUCCESS "Injecting Into x86: (%llu) %wZ\n", (ULONG64)ProcessId, processPath));
		}

		InstallKernelModeApcToInjectDll(ProcessId);
		processInfo->Injected = TRUE;
	}

	return;
}

VOID ProcessCreateCallback(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);

	if (CreateInfo != NULL) {

	}
	else {

	}
}

NTSTATUS InitializeKernelCallbacks()
{
	PAGED_CODE();
	NTSTATUS status;
	
	status = PsSetCreateProcessNotifyRoutineEx(ProcessCreateCallback, FALSE);
	if (!NT_SUCCESS(status)) {
		KdPrint((PANOPTES_PREFIX_ERROR "Driver Failed to Set Process Creation Notify Routine Notify Routine - Ensure /INTEGRITYCHECK is added to the linker options\n"));
		return status;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Set Process Creation Notify Callbacks\n");

	status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
	if (!NT_SUCCESS(status)) {
		NTSTATUS removeStatus = PsSetCreateProcessNotifyRoutineEx(ProcessCreateCallback, TRUE);

		if (!NT_SUCCESS(removeStatus)) {
			KdPrint((PANOPTES_PREFIX_ERROR "Driver Failed to remove callback for Set Process Creation Notify Routine Notify Routine\n"));
			return removeStatus;
		}
		
		KdPrint((PANOPTES_PREFIX_ERROR "Driver Failed to Set Process Load Image Notify Routine - Ensure / INTEGRITYCHECK is added to the linker options\n"));
		
		return status;
	}

	KdPrint((PANOPTES_PREFIX_SUCCESS "Set Image Load Notify Callbacks\n"));

	return STATUS_SUCCESS;
}

VOID RemoveCallbacks() {
	PsSetCreateProcessNotifyRoutineEx(ProcessCreateCallback, TRUE);
	PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
	return;
}
