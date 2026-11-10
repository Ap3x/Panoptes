#include "callbacks.h"
#include <ntstrsafe.h>
#include "shellcode.h"
#include "event_queue.h"
#include "inject_exclusions.h"

RTL_AVL_TABLE g_ProcessList;

// https://github.com/wbenny/injdrv/blob/a8dadf43a09f33c33a3957a250cb7ee05a986608/src/injlib/injlib.c#L404
PVOID
NTAPI
RtlxFindExportedRoutineByName(
	_In_ PVOID DllBase,
	_In_ PANSI_STRING ExportName)
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
		(Function > (PVOID)((ULONG_PTR)ExportDirectory + ExportSize)));

	return Function;
}

/// @brief Checks whether a process's binary signature mitigation policy would make code
/// integrity reject the (non-Microsoft-signed) hook DLL. Chromium-based processes such as
/// msedgewebview2.exe and msedge.exe set this on their children at creation. Loading the DLL
/// into such a process fails, and with a kernel debugger attached CI also breaks in
/// (CipReportAndReprieveUMCIFailure).
/// @return TRUE if the process only allows Microsoft, Store or WHQL signed images. FALSE if it
/// allows other images, or if the policy could not be queried (injection is then attempted,
/// and at worst the load fails).
static BOOLEAN RequiresMicrosoftSignedImages(PEPROCESS Process)
{
	// A kernel handle opened with KernelMode access skips the access check, so this works
	// from any process context
	HANDLE processHandle = NULL;
	NTSTATUS status = ObOpenObjectByPointer(
		Process,
		OBJ_KERNEL_HANDLE,
		NULL,
		0x1000, // PROCESS_QUERY_LIMITED_INFORMATION
		*PsProcessType,
		KernelMode,
		&processHandle);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Panoptes: Failed to open process to query its signature policy, status: 0x%X\n", status);
		return FALSE;
	}

	PROCESS_MITIGATION_POLICY_INFORMATION policyInfo{};
	policyInfo.Policy = ProcessSignaturePolicy;
	status = ZwQueryInformationProcess(processHandle, ProcessMitigationPolicy, &policyInfo, sizeof(policyInfo), NULL);
	ZwClose(processHandle);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Panoptes: Failed to query process signature policy, status: 0x%X\n", status);
		return FALSE;
	}

	// The Audit* flags only log, so the DLL still loads with them
	const PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY &signaturePolicy = policyInfo.Data.SignaturePolicy;
	return signaturePolicy.MicrosoftSignedOnly || signaturePolicy.StoreSignedOnly || signaturePolicy.MitigationOptIn;
}

RTL_GENERIC_COMPARE_RESULTS NTAPI ProcessInfoCompareRoutine(PRTL_AVL_TABLE Table, PVOID FirstStruct, PVOID SecondStruct)
{
	UNREFERENCED_PARAMETER(Table);
	ULONG_PTR first = (ULONG_PTR)((PPANO_PROCESS_INFO)FirstStruct)->ProcessId;
	ULONG_PTR second = (ULONG_PTR)((PPANO_PROCESS_INFO)SecondStruct)->ProcessId;

	if (first < second)
	{
		return GenericLessThan;
	}
	if (first > second)
	{
		return GenericGreaterThan;
	}
	return GenericEqual;
}

PVOID NTAPI ProcessInfoAllocateRoutine(PRTL_AVL_TABLE Table, CLONG ByteSize)
{
	UNREFERENCED_PARAMETER(Table);
	return ExAllocatePool2(POOL_FLAG_NON_PAGED, ByteSize, 'corP');
}

VOID NTAPI ProcessInfoFreeRoutine(PRTL_AVL_TABLE Table, PVOID Buffer)
{
	UNREFERENCED_PARAMETER(Table);
	ExFreePoolWithTag(Buffer, 'corP');
}

PPANO_PROCESS_INFO GetProcessInfo(HANDLE ProcessId)
{
	PANO_PROCESS_INFO key{};
	key.ProcessId = ProcessId;
	return (PPANO_PROCESS_INFO)RtlLookupElementGenericTableAvl(&g_ProcessList, &key);
}

VOID RemoveProcessInfo(HANDLE ProcessId)
{
	PANO_PROCESS_INFO key{};
	key.ProcessId = ProcessId;
	RtlDeleteElementGenericTableAvl(&g_ProcessList, &key);
}

void NTAPI KernelRoutine(PKAPC apc, PKNORMAL_ROUTINE *NormalRoutine, PVOID *NormalContext, PVOID *SystemArgument1, PVOID *SystemArgument2)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	ExFreePool(apc);
}

struct InjectArgs
{
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
		return;
	}

	PPANO_PROCESS_INFO pi = GetProcessInfo(pProcessId);
	if (pi == nullptr)
	{
		DbgPrint("InjectDll - process is not tracked");
		return;
	}

	ANSI_STRING loadDllRoutineName = RTL_CONSTANT_STRING("LoadLibraryExW");
	PVOID shellcodeAddress = RtlxFindExportedRoutineByName(pi->kernel32BaseAddress, &loadDllRoutineName);
	if (shellcodeAddress == nullptr)
	{
		// Queuing an APC to a NULL routine would crash the process
		DbgPrint("Error: LoadLibraryExW was not found in kernel32.");
		return;
	}

	UNICODE_STRING dllToInject;
	PVOID allocatedAddressContainingDllFullPath = nullptr;

	if (pi->is64Bit)
	{
		RtlInitUnicodeString(&dllToInject, L"C:\\Program Files\\Panoptes\\PanoptesDLLx64.dll");
	}
	else
	{
		RtlInitUnicodeString(&dllToInject, L"C:\\Program Files\\Panoptes\\PanoptesDLLx86.dll");
	}

	// Room for the path and its terminator. ZwAllocateVirtualMemory takes and returns a SIZE_T,
	// so it gets its own variable rather than a pointer to the USHORT dllToInject.Length.
	// The allocation is rounded up to whole pages, which are zero-filled
	SIZE_T regionSize = dllToInject.Length + sizeof(WCHAR);

	// A 32-bit process's LoadLibraryExW takes a 32-bit pointer, so its copy of the path must be
	// below 2 GB. A ZeroBits value above 32 is a mask the allocation's address must fit in
	ULONG_PTR zeroBits = pi->is64Bit ? 0 : 0x7FFFFFFF;
	NTSTATUS status = ZwAllocateVirtualMemory(NtCurrentProcess(), &allocatedAddressContainingDllFullPath, zeroBits, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Error: Unable to allocate memory in the target process.");
		return;
	}
	RtlCopyMemory(allocatedAddressContainingDllFullPath, dllToInject.Buffer, dllToInject.Length);

	// MEM_RELEASE frees the whole allocation and requires a size of 0
	SIZE_T releaseSize = 0;

	PKAPC pKapc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), 'tikt'); // Allocate the APC object
	if (!pKapc)
	{
		DbgPrint("Error: Unable to allocate the APC object.");
		ZwFreeVirtualMemory(NtCurrentProcess(), &allocatedAddressContainingDllFullPath, &releaseSize, MEM_RELEASE); // Free the allocated memory
		return;
	}

	// User-mode APCs are delivered by the native 64-bit dispatcher. For a 32-bit process the
	// routine is the 32-bit kernel32's LoadLibraryExW, which must run in 32-bit mode: wrapping
	// the APC makes WOW64 switch modes and call it. Without this the dispatcher runs 32-bit
	// code as 64-bit code and the process crashes
	PVOID apcRoutine = shellcodeAddress;
	PVOID apcContext = allocatedAddressContainingDllFullPath;
	if (!pi->is64Bit)
	{
		status = PsWrapApcWow64Thread(&apcContext, &apcRoutine);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("Error: Unable to wrap the APC for a WOW64 process.");
			ZwFreeVirtualMemory(NtCurrentProcess(), &allocatedAddressContainingDllFullPath, &releaseSize, MEM_RELEASE);
			ExFreePool(pKapc);
			return;
		}
	}

	KeInitializeApc(pKapc, KeGetCurrentThread(), OriginalApcEnvironment, KernelRoutine, NULL, (PKNORMAL_ROUTINE)apcRoutine, UserMode, apcContext); // Initialize the APC

	DbgPrint("Inserting APC to target thread");
	if (!KeInsertQueueApc(pKapc, NULL, NULL, IO_NO_INCREMENT))
	{
		DbgPrint("Error: Unable to insert APC to target thread.");
		ZwFreeVirtualMemory(NtCurrentProcess(), &allocatedAddressContainingDllFullPath, &releaseSize, MEM_RELEASE); // Free the allocated memory
		ExFreePool(pKapc);																											// Free the APC object
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

BOOLEAN Is64BitProcess(PEPROCESS targetProcess)
{
	// Rather than reading EPROCESS.WoW64Process at a fixed offset, which differs between
	// Windows builds
	return PsGetProcessWow64Process(targetProcess) == NULL;
}

VOID LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	PAGED_CODE();

	PPANO_PROCESS_INFO processInfo = GetProcessInfo(ProcessId);
	if (!processInfo || processInfo->Injected || processInfo->ProtectedProcess || processInfo->SignedImagesOnly || processInfo->InjectionExcluded)
	{
		return;
	}

	if (!CanInject(processInfo))
	{
		UNICODE_STRING ntdllLoadImage;
		RtlInitUnicodeString(&ntdllLoadImage, L"ntdll.dll");
		if (wcsstr(FullImageName->Buffer, ntdllLoadImage.Buffer) != NULL)
		{
			processInfo->ntdllLoaded = TRUE;
			return;
		}

		UNICODE_STRING kernel32LoadImage;
		RtlInitUnicodeString(&kernel32LoadImage, L"kernel32.dll");
		if (wcsstr(FullImageName->Buffer, kernel32LoadImage.Buffer) != NULL)
		{
			processInfo->kernel32Loaded = TRUE;
			processInfo->kernel32BaseAddress = ImageInfo->ImageBase;
			return;
		}

		UNICODE_STRING kernelbaseLoadImage;
		RtlInitUnicodeString(&kernelbaseLoadImage, L"KernelBase.dll");
		if (wcsstr(FullImageName->Buffer, kernelbaseLoadImage.Buffer) != NULL)
		{
			processInfo->kernelBaseLoaded = TRUE;
			return;
		}
	}
	else
	{
		PEPROCESS targetProcess = NULL;
		NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &targetProcess);
		if (!NT_SUCCESS(status))
		{
			return;
		}

		PUNICODE_STRING processPath{};
		status = SeLocateProcessImageName(targetProcess, &processPath);
		if (!NT_SUCCESS(status))
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Panoptes: Failed to get process name, status: 0x%X\n", status);
			ObDereferenceObject(targetProcess);
			return;
		}

		// Checked just before injecting, so a list the service sent after the process started
		// still applies. The result is kept so later image loads skip the process
		if (IsInjectionExcluded(processPath))
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[*] Panoptes: Not injecting into (%llu) %wZ: it is in the DontInject list\n", (ULONG64)ProcessId, processPath);
			processInfo->InjectionExcluded = TRUE;
			ExFreePool(processPath);
			ObDereferenceObject(targetProcess);
			return;
		}

		// Checked here rather than at creation, so a policy turned on after creation but
		// before kernel32 loads is also seen. The result is kept so later image loads skip
		// the process without querying again
		if (RequiresMicrosoftSignedImages(targetProcess))
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[*] Panoptes: Not injecting into (%llu) %wZ: it only loads Microsoft-signed images\n", (ULONG64)ProcessId, processPath);
			processInfo->SignedImagesOnly = TRUE;
			ExFreePool(processPath);
			ObDereferenceObject(targetProcess);
			return;
		}

		if (processInfo->is64Bit)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Injecting into x64: (%llu) %wZ\n", (ULONG64)ProcessId, processPath);
		}
		else
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Injecting Into x86: (%llu) %wZ\n", (ULONG64)ProcessId, processPath);
		}

		ExFreePool(processPath);
		ObDereferenceObject(targetProcess);

		InstallKernelModeApcToInjectDll(ProcessId);
		processInfo->Injected = TRUE;
	}
	return;
}

VOID ProcessCreateCallback(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	if (CreateInfo != NULL)
	{
		// Protected processes are still tracked and reported; ProtectedProcess makes
		// LoadImageNotifyRoutine skip injecting into them
		PANO_PROCESS_INFO processInfo{};
		processInfo.ProcessId = ProcessId;
		processInfo.is64Bit = Is64BitProcess(Process);
		processInfo.ProtectedProcess = PsIsProtectedProcess(Process);
		// The signature policy is checked in LoadImageNotifyRoutine just before injecting

		if (!RtlInsertElementGenericTableAvl(&g_ProcessList, &processInfo, sizeof(processInfo), NULL))
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Panoptes: Failed to track process %llu\n", (ULONG64)ProcessId);
		}

		// ImageFileName is only valid when FileOpenNameAvailable is set
		PCUNICODE_STRING imageName = CreateInfo->FileOpenNameAvailable ? CreateInfo->ImageFileName : NULL;
		// CommandLine can be NULL (e.g. minimal/pico processes)
		PCUNICODE_STRING commandLine = CreateInfo->CommandLine;
		PanoReportProcessEvent(
			PANO_EVENT_PROCESS_CREATED,
			(UINT64)ProcessId,
			(UINT64)CreateInfo->ParentProcessId,
			(UINT64)CreateInfo->CreatingThreadId.UniqueProcess,
			(UINT64)CreateInfo->CreatingThreadId.UniqueThread,
			imageName ? imageName->Buffer : NULL,
			imageName ? imageName->Length / sizeof(WCHAR) : 0,
			commandLine ? commandLine->Buffer : NULL,
			commandLine ? commandLine->Length / sizeof(WCHAR) : 0);


	}
	else
	{
		RemoveProcessInfo(ProcessId);
		PanoReportProcessEvent(PANO_EVENT_PROCESS_TERMINATED, (UINT64)ProcessId, 0, 0, 0, NULL, 0, NULL, 0);
	}
}

NTSTATUS InitializeKernelCallbacks()
{
	PAGED_CODE();

	RtlInitializeGenericTableAvl(&g_ProcessList, ProcessInfoCompareRoutine, ProcessInfoAllocateRoutine, ProcessInfoFreeRoutine, NULL);
	NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(ProcessCreateCallback, FALSE);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Panoptes: Driver Failed to Set Process Creation Notify Routine Notify Routine - Ensure /INTEGRITYCHECK is added to the linker options\n");
		return status;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Set Process Creation Notify Callbacks\n");

	status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
	if (!NT_SUCCESS(status))
	{
		NTSTATUS removeStatus = PsSetCreateProcessNotifyRoutineEx(ProcessCreateCallback, TRUE);
		if (!NT_SUCCESS(removeStatus))
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Panoptes: Driver Failed to remove callback for Set Process Creation Notify Routine Notify Routine\n");
			return removeStatus;
		}
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Panoptes: Driver Failed to Set Process Load Image Notify Routine - Ensure /INTEGRITYCHECK is added to the linker options\n");
		return status;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Set Image Load Notify Callbacks\n");

	return STATUS_SUCCESS;
}

VOID RemoveCallbacks()
{
	PsSetCreateProcessNotifyRoutineEx(ProcessCreateCallback, TRUE);
	PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);

	PVOID entry;
	while ((entry = RtlGetElementGenericTableAvl(&g_ProcessList, 0)) != NULL)
	{
		RtlDeleteElementGenericTableAvl(&g_ProcessList, entry);
	}
	return;
}
