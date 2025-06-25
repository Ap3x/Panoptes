#include "callbacks.h"
#include "inject.h"
#include "pano_query.h"
#include <ntstrsafe.h>
#include "shellcode.h"


LIST_ENTRY g_ProcessList{};
KSPIN_LOCK g_ProcessListLock{};
PVOID g_ObRegistrationHandle{};

PVOID
NTAPI
RtlxFindExportedRoutineByName(
	_In_ PVOID DllBase,
	_In_ PANSI_STRING ExportName
)
{
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

//QUERY_INFO_PROCESS ZwQueryInformationProcessPtr;
//
//NTSTATUS InitializeZwQueryInformationProcessCallback() {
//	UNICODE_STRING routineName;
//	RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
//	//https://stackoverflow.com/questions/3707133/how-to-use-zwqueryinformationprocess-to-get-processimagefilename-in-a-kernel-dri
//	ZwQueryInformationProcessPtr = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);
//	if (ZwQueryInformationProcessPtr == NULL) {
//		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Panoptes: Cannot resolve ZwQueryInformationProcess\n");
//		return STATUS_INVALID_HANDLE;
//	}
//
//	return STATUS_SUCCESS;
//}

OB_PREOP_CALLBACK_STATUS PreOperationCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	PAGED_CODE();
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);
	//if (OperationInformation->ObjectType == *IoDeviceObjectType)
	//{
	//	ULONG returnLength; 
	//	PDEVICE_OBJECT deviceObject = (PDEVICE_OBJECT)OperationInformation->Object;
	//	// Query the object name
	//	NTSTATUS status = ObQueryNameString(deviceObject, NULL, 0, &returnLength);
	//	if (status != STATUS_INFO_LENGTH_MISMATCH)
	//	{
	//		return OB_PREOP_SUCCESS;
	//	}
	//	// Allocate memory for the name information
	//	POBJECT_NAME_INFORMATION objectNameInfo = NULL;
	//	objectNameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, returnLength, 'NveD');
	//	if (objectNameInfo == NULL)
	//	{
	//		return OB_PREOP_SUCCESS;
	//	}
	//	// Get the object name
	//	UNICODE_STRING deviceName;
	//	// Initialize the UNICODE_STRING
	//	RtlInitUnicodeString(&deviceName, NULL);
	//	// Allocate a buffer for the device name
	//	deviceName.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, returnLength, 'NveD');
	//	if (deviceName.Buffer == NULL)
	//	{
	//		return OB_PREOP_SUCCESS;
	//	}
	//	status = ObQueryNameString(deviceObject, objectNameInfo, returnLength, &returnLength);
	//	if (NT_SUCCESS(status))
	//	{
	//		// Copy the name to the output parameter
	//		RtlCopyUnicodeString(&deviceName, &objectNameInfo->Name);
	//	}
	//	if (deviceName.Buffer && wcsstr(deviceName.Buffer, L"\\Device\\NamedPipe\\") != NULL)
	//	{
	//		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Named Pipe created: %wZ\n", deviceName.Buffer);
	//	}
	//	return OB_PREOP_SUCCESS;
	//}

	return OB_PREOP_SUCCESS;
}

//void PostOperationCallback(PVOID RegistrationContext,POB_POST_OPERATION_INFORMATION OperationInformation)
//{
//	UNREFERENCED_PARAMETER(OperationInformation);
//	UNREFERENCED_PARAMETER(RegistrationContext);
//}

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

struct InjectArgs {
	PUNICODE_STRING DLLPath;
	PUNICODE_STRING DllName;
	PVOID DllHandle;
};

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
			//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Loaded ntdll in %llu\n", (ULONG64)ProcessId);
			processInfo->ntdllLoaded = TRUE;
			return;
		}

		UNICODE_STRING kernel32LoadImage;
		RtlInitUnicodeString(&kernel32LoadImage, L"kernel32.dll");
		if (wcsstr(FullImageName->Buffer, kernel32LoadImage.Buffer) != NULL) {
			//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Loaded kernel32 in %llu\n", (ULONG64)ProcessId);
			processInfo->kernel32Loaded = TRUE;
			processInfo->kernel32BaseAddress = ImageInfo->ImageBase;
			return;
		}

		UNICODE_STRING kernelbaseLoadImage;
		RtlInitUnicodeString(&kernelbaseLoadImage, L"KernelBase.dll");
		if (wcsstr(FullImageName->Buffer, kernelbaseLoadImage.Buffer) != NULL) {
			//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Loaded kernelbase in %llu\n", (ULONG64)ProcessId);
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
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Panoptes: Failed to get process name, status: 0x%X\n", status);
			return;
		}

		processInfo->is64Bit = Is64BitProcess(targetProcess);
		if (processInfo->is64Bit) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Injecting into x64: (%llu) %wZ\n", (ULONG64)ProcessId, processPath);
		}
		else {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Injecting Into x86: (%llu) %wZ\n", (ULONG64)ProcessId, processPath);
		}

		InstallKernelModeApcToInjectDll(ProcessId);
		processInfo->Injected = TRUE;
	}

	//PEPROCESS ProcessStruct;
	//PsLookupProcessByProcessId(ProcessId, &ProcessStruct);
	// We dont want to deal with trying to inject into protected processes
	//if (PsIsProtectedProcess(ProcessStruct))
	//{
	//	//RemoveProcessInfoByProcessId(ProcessId);
	//	return;
	//}
	//if (ZwQueryInformationProcessPtr == NULL)
	//{
	//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Panoptes: Cannot resolve ZwQueryInformationProcess\n");
	//	InitializeZwQueryInformationProcessCallback();
	//}
	//ZwQueryInformationProcessPtr(
	//	ProcessStruct,
	//	ProcessBasicInformation,
	//	NULL,
	//	0,
	//	NULL
	//);
	//HANDLE processHandle;
	//NTSTATUS status = ObOpenObjectByPointer(
	//	ProcessStruct,
	//	OBJ_KERNEL_HANDLE,
	//	NULL,
	//	PROCESS_ALL_ACCESS,
	//	*PsProcessType,
	//	KernelMode,
	//	&processHandle
	//);
	//PROCESS_BASIC_INFORMATION pbi;
	//ULONG returnLength;
	//status = ZwQueryInformationProcessPtr(
	//	processHandle,
	//	ProcessBasicInformation,
	//	&pbi,
	//	sizeof(PROCESS_BASIC_INFORMATION),
	//	&returnLength
	//);
	//if (!processInfo->LdrLoadDllRoutineAddress) {
	//	ANSI_STRING ldrLoadDll;
	//	RtlInitAnsiString(&ldrLoadDll, "LdrLoadDll");
	//	UNICODE_STRING kernel32LoadImage;
	//	RtlInitUnicodeString(&kernel32LoadImage, L"*\\ntdll.dll");
	//	if (FsRtlIsNameInExpression(&kernel32LoadImage, FullImageName, TRUE, NULL)) {
	//		processInfo->LdrLoadDllRoutineAddress = RtlFindExportedRoutineByName((PVOID)ImageInfo->ImageBase, ldrLoadDll.Buffer);
	//		processInfo->NtdllLoaded = TRUE;
	//		return;
	//	}
	//}
	//else
	//{
	//	//UINT64 Process, ProcessHead;
	//	//NTSTATUS status = PsLookupProcessByProcessId(ProcessId, (PEPROCESS*)&ProcessHead);
	//	//if (!NT_SUCCESS(status))
	//	//{
	//	//	return;
	//	//}
	//	//Process = ProcessHead;
	//	//UINT64 Thread, ThreadHead = *(UINT64*)(Process + 0x5e0) - 0x538; // Thread->ThreadListHead.Flink
	//	//Thread = ThreadHead;
	//	//bool found = false;
	//	//do {
	//	//	if (*(UINT32*)(Thread + 0x74) & (1 << 4)) { // Thread.Tcb.MiscFlags & Alertable
	//	//		found = true;
	//	//		break;
	//	//	}
	//	//	Thread = *(UINT64*)(Thread + 0x538) - 0x538; // Thread->ThreadListEntry.Flink
	//	//} while (Thread != ThreadHead);
	//	DbgBreakPoint();
	//	InjectDLL(ProcessId, processInfo);
	//}

	return;
}

VOID ProcessCreateCallback(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);

	if (CreateInfo != NULL) {
		UNICODE_STRING onlyProc;
		RtlInitUnicodeString(&onlyProc, L"die.exe");
		if (wcsstr(CreateInfo->ImageFileName->Buffer, onlyProc.Buffer) != NULL) {
			PPANO_PROCESS_INFO processInfo = (PPANO_PROCESS_INFO)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PANO_PROCESS_INFO), 'corP');
			if (processInfo) {
				processInfo->ProcessId = ProcessId;
				processInfo->Injected = FALSE;
				processInfo->ntdllLoaded = FALSE;
				processInfo->kernel32Loaded = FALSE;
				processInfo->kernelBaseLoaded = FALSE;

				InsertTailList(&g_ProcessList, &processInfo->ListEntry);
			}

			PROCESS_MITIGATION_POLICY_INFORMATION policyInfo{};
			NTSTATUS status = QueryProcessMitigationPolicy(ProcessId, &policyInfo);
			if (!NT_SUCCESS(status)) {
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Panoptes: Failed to get process mitigation policy, status: 0x%X\n", status);
			}
		}

		//if (CreateInfo->ImageFileName->Buffer != NULL) {
			//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Process Starting: %wZ\n", CreateInfo->ImageFileName->Buffer);


		//	//EventWriteProcessCreation(NULL, (UINT64)ProcessId, processPath->Buffer, (UINT64)CreateInfo->ParentProcessId, 0, (UINT64)&policyInfo);
		//	EventWriteProcessCreation(NULL, (UINT64)ProcessId, processPath->Buffer, (UINT64)CreateInfo->ParentProcessId, 0, 0);
		//	ExFreePool(processPath->Buffer);
		//}
	}
	else {
		RemoveProcessInfo(ProcessId);
	}
}

NTSTATUS InitializeKernelCallbacks()
{
	PAGED_CODE();
	NTSTATUS status;
	//UNICODE_STRING callbackAltitude;
	////https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers
	//RtlInitUnicodeString(&callbackAltitude, L"1931");

	//OB_CALLBACK_REGISTRATION callbackRegistration;
	//OB_OPERATION_REGISTRATION operationRegistration;
	//RtlSecureZeroMemory(&operationRegistration, sizeof(OB_OPERATION_REGISTRATION));
	//RtlSecureZeroMemory(&callbackRegistration, sizeof(OB_CALLBACK_REGISTRATION));
	//operationRegistration.ObjectType = PsProcessType;
	//operationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	//operationRegistration.PreOperation = PreOperationCallback;
	////operationRegistration.PostOperation = PostOperationCallback;
	//operationRegistration.PostOperation = NULL;

	//callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	//callbackRegistration.OperationRegistrationCount = 1;
	//callbackRegistration.Altitude = callbackAltitude;
	//callbackRegistration.OperationRegistration = &operationRegistration;
	//callbackRegistration.RegistrationContext = NULL;

	//status = ObRegisterCallbacks(&callbackRegistration, &g_ObRegistrationHandle);
	//if (!NT_SUCCESS(status)) {
	//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Panoptes: Driver Failed to Set Object Registration Callbacks - Ensure /INTEGRITYCHECK is added to the linker options\n");
	//	return status;
	//}
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Set Object Registration Callbacks\n");

	InitializeListHead(&g_ProcessList);
	//KeInitializeSpinLock(&g_ProcessListLock);
	status = PsSetCreateProcessNotifyRoutineEx(ProcessCreateCallback, FALSE);
	if (!NT_SUCCESS(status)) {
		//ObUnRegisterCallbacks(g_ObRegistrationHandle);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Panoptes: Driver Failed to Set Process Creation Notify Routine Notify Routine - Ensure /INTEGRITYCHECK is added to the linker options\n");
		return status;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Set Process Creation Notify Callbacks\n");

	status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
	if (!NT_SUCCESS(status)) {
		NTSTATUS removeStatus = PsSetCreateProcessNotifyRoutineEx(ProcessCreateCallback, TRUE);
		if (!NT_SUCCESS(removeStatus)) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Panoptes: Driver Failed to remove callback for Set Process Creation Notify Routine Notify Routine\n");
			return removeStatus;
		}
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Panoptes: Driver Failed to Set Process Load Image Notify Routine - Ensure /INTEGRITYCHECK is added to the linker options\n");
		return status;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Set Image Load Notify Callbacks\n");

	return STATUS_SUCCESS;
}

VOID RemoveCallbacks() {
	//ObUnRegisterCallbacks(g_ObRegistrationHandle);
	PsSetCreateProcessNotifyRoutineEx(ProcessCreateCallback, TRUE);
	PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
	return;
}
