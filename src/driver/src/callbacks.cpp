#include "callbacks.h"
#include <ntstrsafe.h>
#include "shellcode.h"
#include "event_queue.h"
#include "inject_exclusions.h"

RTL_AVL_TABLE g_ProcessList;
LARGE_INTEGER g_RegistryCookie;

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

#pragma region Registry Events

#define PANO_REGISTRY_POOL_TAG 'gRoP' // "PoRg"

// Decides whether a registry operation on the current thread is reported, and fills in who made
// it. The service's own registry activity is not reported, as with its file activity
static BOOLEAN BeginRegistryEvent(UINT64* ProcessId, UINT64* ThreadId, UINT32* Flags)
{
	*ProcessId = (UINT64)PsGetCurrentProcessId();
	if (EventQueueIsConsumerProcess(*ProcessId))
	{
		return FALSE;
	}

	*ThreadId = (UINT64)PsGetCurrentThreadId();
	*Flags = (ExGetPreviousMode() == KernelMode) ? PANO_FLAG_KERNEL_MODE_CALLER : 0;
	return TRUE;
}

// Gets the full name (\REGISTRY\MACHINE\...) of a key object. Release a non-NULL result with
// CmCallbackReleaseKeyObjectIDEx
static PCUNICODE_STRING GetRegistryKeyName(PVOID KeyObject)
{
	PCUNICODE_STRING name = NULL;
	if (KeyObject == NULL || !NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&g_RegistryCookie, KeyObject, NULL, &name, 0)))
	{
		return NULL;
	}
	return name;
}

// Copies a buffer passed with a registry operation into pool. For a call from user mode the
// buffer can be the caller's own memory: the system call has checked that it is user memory, but
// the caller can still change or free it at any time, so it is only read under __try. Returns
// NULL and sets *Failed if it could not be copied. Free a non-NULL result with ExFreePoolWithTag
static PVOID CaptureRegistryBuffer(const void* Buffer, SIZE_T Length, UINT32* Flags)
{
	if (Buffer == NULL || Length == 0)
	{
		return NULL;
	}

	PVOID copy = ExAllocatePool2(POOL_FLAG_PAGED, Length, PANO_REGISTRY_POOL_TAG);
	if (copy == NULL)
	{
		*Flags |= PANO_FLAG_CAPTURE_FAILED;
		return NULL;
	}

	__try
	{
		RtlCopyMemory(copy, Buffer, Length);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ExFreePoolWithTag(copy, PANO_REGISTRY_POOL_TAG);
		*Flags |= PANO_FLAG_CAPTURE_FAILED;
		return NULL;
	}
	return copy;
}

// Copies a UNICODE_STRING passed with a registry operation into pool, under the same rules as
// CaptureRegistryBuffer (the UNICODE_STRING itself is read under __try too). Returns NULL with
// *Length 0 for a missing or empty string. Free a non-NULL result with ExFreePoolWithTag
static PWCH CaptureRegistryString(PCUNICODE_STRING String, UINT32* Length, UINT32* Flags)
{
	*Length = 0;
	if (String == NULL)
	{
		return NULL;
	}

	UNICODE_STRING string;
	__try
	{
		string = *String;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		*Flags |= PANO_FLAG_CAPTURE_FAILED;
		return NULL;
	}

	UINT32 length = string.Length / sizeof(WCHAR);
	PWCH copy = (PWCH)CaptureRegistryBuffer(string.Buffer, length * sizeof(WCHAR), Flags);
	if (copy != NULL)
	{
		*Length = length;
	}
	return copy;
}

static void FreeRegistryBuffer(PVOID Buffer)
{
	if (Buffer != NULL)
	{
		ExFreePoolWithTag(Buffer, PANO_REGISTRY_POOL_TAG);
	}
}

static void ReleaseRegistryKeyName(PCUNICODE_STRING KeyName)
{
	if (KeyName != NULL)
	{
		CmCallbackReleaseKeyObjectIDEx(KeyName);
	}
}

// Reports an event that carries only a key name: the full name of KeyObject
static void ReportRegistryKeyEvent(PANO_EVENT_TYPE Type, PVOID KeyObject)
{
	UINT64 processId, threadId;
	UINT32 flags;
	if (!BeginRegistryEvent(&processId, &threadId, &flags))
	{
		return;
	}

	PCUNICODE_STRING keyName = GetRegistryKeyName(KeyObject);
	if (keyName == NULL)
	{
		flags |= PANO_FLAG_CAPTURE_FAILED;
	}

	PanoReportRegistryEvent(
		Type,
		processId,
		threadId,
		flags,
		0,
		0,
		keyName ? keyName->Buffer : NULL,
		keyName ? keyName->Length / sizeof(WCHAR) : 0,
		NULL,
		0,
		NULL,
		0);

	ReleaseRegistryKeyName(keyName);
}

// Reports a value about to be written. Persistence (Run keys, services, IFEO, COM hijacks) and
// defence tampering are mostly value writes, so the value name and the start of its data are sent
static void ReportSetValueKey(PREG_SET_VALUE_KEY_INFORMATION Info)
{
	UINT64 processId, threadId;
	UINT32 flags;
	if (Info == NULL || !BeginRegistryEvent(&processId, &threadId, &flags))
	{
		return;
	}

	UINT32 valueNameLength;
	PWCH valueName = CaptureRegistryString(Info->ValueName, &valueNameLength, &flags);

	UINT32 dataLength = min(Info->DataSize, (ULONG)PANO_MAX_REGISTRY_DATA_SIZE);
	if (Info->DataSize > PANO_MAX_REGISTRY_DATA_SIZE)
	{
		flags |= PANO_FLAG_DATA_TRUNCATED;
	}
	PVOID data = CaptureRegistryBuffer(Info->Data, dataLength, &flags);
	if (data == NULL)
	{
		dataLength = 0;
	}

	PCUNICODE_STRING keyName = GetRegistryKeyName(Info->Object);
	if (keyName == NULL)
	{
		flags |= PANO_FLAG_CAPTURE_FAILED;
	}

	PanoReportRegistryEvent(
		PANO_EVENT_REGISTRY_SET_VALUE,
		processId,
		threadId,
		flags,
		Info->Type,
		Info->DataSize,
		keyName ? keyName->Buffer : NULL,
		keyName ? keyName->Length / sizeof(WCHAR) : 0,
		valueName,
		valueNameLength,
		data,
		dataLength);

	ReleaseRegistryKeyName(keyName);
	FreeRegistryBuffer(valueName);
	FreeRegistryBuffer(data);
}

// Reports a key about to be saved to a file. Saving HKLM\SAM, SECURITY or SYSTEM is how
// credentials are dumped with reg save, so the destination file is sent too
static void ReportSaveKey(PREG_SAVE_KEY_INFORMATION Info)
{
	UINT64 processId, threadId;
	UINT32 flags;
	if (Info == NULL || !BeginRegistryEvent(&processId, &threadId, &flags))
	{
		return;
	}

	// The handle belongs to the caller, and pre callbacks run on the caller's thread. It is
	// looked up with the caller's mode so a user mode caller cannot name a kernel handle
	POBJECT_NAME_INFORMATION fileName = NULL;
	PFILE_OBJECT fileObject = NULL;
	if (NT_SUCCESS(ObReferenceObjectByHandle(Info->FileHandle, 0, *IoFileObjectType, ExGetPreviousMode(), (PVOID*)&fileObject, NULL)))
	{
		if (!NT_SUCCESS(IoQueryFileDosDeviceName(fileObject, &fileName)))
		{
			fileName = NULL;
		}
		ObDereferenceObject(fileObject);
	}

	PCUNICODE_STRING keyName = GetRegistryKeyName(Info->Object);
	if (keyName == NULL || fileName == NULL)
	{
		flags |= PANO_FLAG_CAPTURE_FAILED;
	}

	PanoReportRegistryEvent(
		PANO_EVENT_REGISTRY_SAVE_KEY,
		processId,
		threadId,
		flags,
		Info->Format,
		0,
		keyName ? keyName->Buffer : NULL,
		keyName ? keyName->Length / sizeof(WCHAR) : 0,
		fileName ? fileName->Name.Buffer : NULL,
		fileName ? fileName->Name.Length / sizeof(WCHAR) : 0,
		NULL,
		0);

	if (keyName != NULL)
	{
		CmCallbackReleaseKeyObjectIDEx(keyName);
	}
	if (fileName != NULL)
	{
		ExFreePool(fileName);
	}
}

// Reports a key's security descriptor about to be changed, e.g. to stop defenders from reading
// or removing a persistence key
static void ReportSetKeySecurity(PREG_SET_KEY_SECURITY_INFORMATION Info)
{
	UINT64 processId, threadId;
	UINT32 flags;
	if (Info == NULL || !BeginRegistryEvent(&processId, &threadId, &flags))
	{
		return;
	}

	SECURITY_INFORMATION securityInformation = 0;
	__try
	{
		if (Info->SecurityInformation != NULL)
		{
			securityInformation = *Info->SecurityInformation;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		flags |= PANO_FLAG_CAPTURE_FAILED;
	}

	PCUNICODE_STRING keyName = GetRegistryKeyName(Info->Object);
	if (keyName == NULL)
	{
		flags |= PANO_FLAG_CAPTURE_FAILED;
	}

	PanoReportRegistryEvent(
		PANO_EVENT_REGISTRY_SET_KEY_SECURITY,
		processId,
		threadId,
		flags,
		securityInformation,
		0,
		keyName ? keyName->Buffer : NULL,
		keyName ? keyName->Length / sizeof(WCHAR) : 0,
		NULL,
		0,
		NULL,
		0);

	if (keyName != NULL)
	{
		CmCallbackReleaseKeyObjectIDEx(keyName);
	}
}

// Reports a key that was created. A create call on a key that already exists just opens it,
// which happens constantly, so only keys that are new are reported
static void ReportCreateKey(PREG_POST_OPERATION_INFORMATION Info)
{
	if (Info == NULL || !NT_SUCCESS(Info->Status) || Info->Object == NULL)
	{
		return;
	}

	PREG_CREATE_KEY_INFORMATION pre = (PREG_CREATE_KEY_INFORMATION)Info->PreInformation;
	if (pre == NULL)
	{
		return;
	}

	// Disposition can point at the caller's memory
	ULONG disposition = 0;
	__try
	{
		if (pre->Disposition != NULL)
		{
			disposition = *pre->Disposition;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return;
	}

	if (disposition == REG_CREATED_NEW_KEY)
	{
		ReportRegistryKeyEvent(PANO_EVENT_REGISTRY_CREATE_KEY, Info->Object);
	}
}

// Builds "<Parent>\<Child>" in pool. Free a non-NULL result with ExFreePoolWithTag
static PWCH JoinRegistryPath(PCUNICODE_STRING Parent, const WCHAR* Child, UINT32 ChildLength, UINT32* Length)
{
	UINT32 parentLength = Parent->Length / sizeof(WCHAR);
	UINT32 length = parentLength + 1 + ChildLength;
	PWCH path = (PWCH)ExAllocatePool2(POOL_FLAG_PAGED, (SIZE_T)length * sizeof(WCHAR), PANO_REGISTRY_POOL_TAG);
	if (path == NULL)
	{
		return NULL;
	}

	RtlCopyMemory(path, Parent->Buffer, parentLength * sizeof(WCHAR));
	path[parentLength] = L'\\';
	RtlCopyMemory(path + parentLength + 1, Child, ChildLength * sizeof(WCHAR));
	*Length = length;
	return path;
}

// Reports a hive file that was loaded into the registry. Attackers load a hive to edit an offline
// user's settings, or a copied SAM or SECURITY hive to read it
static void ReportLoadKey(PREG_POST_OPERATION_INFORMATION Info)
{
	UINT64 processId, threadId;
	UINT32 flags;
	if (Info == NULL || !NT_SUCCESS(Info->Status) || Info->PreInformation == NULL ||
		!BeginRegistryEvent(&processId, &threadId, &flags))
	{
		return;
	}

	PREG_LOAD_KEY_INFORMATION pre = (PREG_LOAD_KEY_INFORMATION)Info->PreInformation;

	UINT32 keyNameLength;
	PWCH keyName = CaptureRegistryString(pre->KeyName, &keyNameLength, &flags);

	// The name is relative to the root key in Object when the caller passed one (e.g. HKLM),
	// so the root's name is put in front of it
	if (keyName != NULL && keyName[0] != L'\\' && pre->Object != NULL)
	{
		PCUNICODE_STRING rootName = GetRegistryKeyName(pre->Object);
		if (rootName != NULL)
		{
			UINT32 fullLength;
			PWCH fullName = JoinRegistryPath(rootName, keyName, keyNameLength, &fullLength);
			if (fullName != NULL)
			{
				FreeRegistryBuffer(keyName);
				keyName = fullName;
				keyNameLength = fullLength;
			}
			ReleaseRegistryKeyName(rootName);
		}
	}

	UINT32 fileNameLength;
	PWCH fileName = CaptureRegistryString(pre->SourceFile, &fileNameLength, &flags);
	if (keyName == NULL || fileName == NULL)
	{
		flags |= PANO_FLAG_CAPTURE_FAILED;
	}

	PanoReportRegistryEvent(
		PANO_EVENT_REGISTRY_LOAD_KEY,
		processId,
		threadId,
		flags,
		pre->Flags,
		0,
		keyName,
		keyNameLength,
		fileName,
		fileNameLength,
		NULL,
		0);

	FreeRegistryBuffer(keyName);
	FreeRegistryBuffer(fileName);
}

// Reports a key's hive file being replaced at the next boot, which swaps in a hive the
// attacker prepared offline
static void ReportReplaceKey(PREG_POST_OPERATION_INFORMATION Info)
{
	UINT64 processId, threadId;
	UINT32 flags;
	if (Info == NULL || !NT_SUCCESS(Info->Status) || Info->PreInformation == NULL ||
		!BeginRegistryEvent(&processId, &threadId, &flags))
	{
		return;
	}

	PREG_REPLACE_KEY_INFORMATION pre = (PREG_REPLACE_KEY_INFORMATION)Info->PreInformation;

	UINT32 newFileLength;
	PWCH newFile = CaptureRegistryString(pre->NewFileName, &newFileLength, &flags);

	// The old file name goes in Data, as the event has room for only two names
	UINT32 oldFileLength;
	PWCH oldFile = CaptureRegistryString(pre->OldFileName, &oldFileLength, &flags);
	UINT32 oldFileBytes = oldFileLength * sizeof(WCHAR);
	UINT32 oldFileDataLength = min(oldFileBytes, (UINT32)PANO_MAX_REGISTRY_DATA_SIZE);
	if (oldFileBytes > PANO_MAX_REGISTRY_DATA_SIZE)
	{
		flags |= PANO_FLAG_DATA_TRUNCATED;
	}

	PCUNICODE_STRING keyName = GetRegistryKeyName(pre->Object);
	if (keyName == NULL || newFile == NULL || oldFile == NULL)
	{
		flags |= PANO_FLAG_CAPTURE_FAILED;
	}

	PanoReportRegistryEvent(
		PANO_EVENT_REGISTRY_REPLACE_KEY,
		processId,
		threadId,
		flags,
		0,
		oldFileBytes,
		keyName ? keyName->Buffer : NULL,
		keyName ? keyName->Length / sizeof(WCHAR) : 0,
		newFile,
		newFileLength,
		oldFile,
		oldFileDataLength);

	ReleaseRegistryKeyName(keyName);
	FreeRegistryBuffer(newFile);
	FreeRegistryBuffer(oldFile);
}

// A key's old name, kept from its pre-rename notification to its post-rename one. Once the key
// is renamed, its object only gives the new name
typedef struct _PANO_RENAME_KEY_CONTEXT
{
	UINT32 Length;
	WCHAR Name[1];
} PANO_RENAME_KEY_CONTEXT, * PPANO_RENAME_KEY_CONTEXT;

// Saves the key's name before it is renamed. The registry hands CallContext to the matching
// post notification, which reports the rename and frees it. If the driver unloads between the
// two, that post notification never comes and the context is leaked
static void BeginRenameKey(PREG_RENAME_KEY_INFORMATION Info)
{
	UINT64 processId, threadId;
	UINT32 flags;
	if (Info == NULL || !BeginRegistryEvent(&processId, &threadId, &flags))
	{
		return;
	}

	PCUNICODE_STRING keyName = GetRegistryKeyName(Info->Object);
	if (keyName == NULL)
	{
		return;
	}

	UINT32 length = keyName->Length / sizeof(WCHAR);
	PPANO_RENAME_KEY_CONTEXT context = (PPANO_RENAME_KEY_CONTEXT)ExAllocatePool2(
		POOL_FLAG_PAGED,
		FIELD_OFFSET(PANO_RENAME_KEY_CONTEXT, Name) + (SIZE_T)length * sizeof(WCHAR),
		PANO_REGISTRY_POOL_TAG);
	if (context != NULL)
	{
		context->Length = length;
		RtlCopyMemory(context->Name, keyName->Buffer, length * sizeof(WCHAR));
		Info->CallContext = context;
	}

	ReleaseRegistryKeyName(keyName);
}

// Reports a renamed key with its old and new full names
static void ReportRenameKey(PREG_POST_OPERATION_INFORMATION Info)
{
	if (Info == NULL || Info->CallContext == NULL)
	{
		return;
	}

	PPANO_RENAME_KEY_CONTEXT context = (PPANO_RENAME_KEY_CONTEXT)Info->CallContext;
	UINT64 processId, threadId;
	UINT32 flags;
	if (NT_SUCCESS(Info->Status) && BeginRegistryEvent(&processId, &threadId, &flags))
	{
		PCUNICODE_STRING newName = GetRegistryKeyName(Info->Object);
		if (newName == NULL)
		{
			flags |= PANO_FLAG_CAPTURE_FAILED;
		}

		PanoReportRegistryEvent(
			PANO_EVENT_REGISTRY_RENAME_KEY,
			processId,
			threadId,
			flags,
			0,
			0,
			context->Name,
			context->Length,
			newName ? newName->Buffer : NULL,
			newName ? newName->Length / sizeof(WCHAR) : 0,
			NULL,
			0);

		ReleaseRegistryKeyName(newName);
	}

	ExFreePoolWithTag(context, PANO_REGISTRY_POOL_TAG);
}

// True if a key is in a hive that holds credentials: HKLM\SAM (local account hashes) or
// HKLM\SECURITY (LSA secrets, cached domain logons)
static BOOLEAN IsCredentialKey(PCUNICODE_STRING KeyName)
{
	static const UNICODE_STRING roots[] = {
		RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SAM"),
		RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SECURITY"),
	};

	for (const UNICODE_STRING& root : roots)
	{
		if (RtlPrefixUnicodeString(&root, KeyName, TRUE) &&
			(KeyName->Length == root.Length || KeyName->Buffer[root.Length / sizeof(WCHAR)] == L'\\'))
		{
			return TRUE;
		}
	}
	return FALSE;
}

// Reports a value read from a key holding credentials. Value reads happen constantly across the
// system, so reads of any other key are dropped. The value's data is never sent: it would put
// password hashes and secrets in the log
static void ReportQueryValueKey(PREG_POST_OPERATION_INFORMATION Info)
{
	UINT64 processId, threadId;
	UINT32 flags;
	if (Info == NULL || !NT_SUCCESS(Info->Status) || Info->PreInformation == NULL ||
		!BeginRegistryEvent(&processId, &threadId, &flags))
	{
		return;
	}

	PCUNICODE_STRING keyName = GetRegistryKeyName(Info->Object);
	if (keyName == NULL)
	{
		return;
	}
	if (!IsCredentialKey(keyName))
	{
		ReleaseRegistryKeyName(keyName);
		return;
	}

	PREG_QUERY_VALUE_KEY_INFORMATION pre = (PREG_QUERY_VALUE_KEY_INFORMATION)Info->PreInformation;
	UINT32 valueNameLength;
	PWCH valueName = CaptureRegistryString(pre->ValueName, &valueNameLength, &flags);

	PanoReportRegistryEvent(
		PANO_EVENT_REGISTRY_QUERY_VALUE,
		processId,
		threadId,
		flags,
		(UINT32)pre->KeyValueInformationClass,
		0,
		keyName->Buffer,
		keyName->Length / sizeof(WCHAR),
		valueName,
		valueNameLength,
		NULL,
		0);

	ReleaseRegistryKeyName(keyName);
	FreeRegistryBuffer(valueName);
}

#pragma endregion

NTSTATUS RegistryCallbackFunction(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
	UNREFERENCED_PARAMETER(CallbackContext);

	// Argument1 holds the REG_NOTIFY_CLASS value itself, not a pointer to it
	REG_NOTIFY_CLASS regClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
	switch (regClass)
	{
		case RegNtPreSetValueKey:
			ReportSetValueKey((PREG_SET_VALUE_KEY_INFORMATION)Argument2);
			break;
		case RegNtPreSaveKey:
			ReportSaveKey((PREG_SAVE_KEY_INFORMATION)Argument2);
			break;
		case RegNtPreSetKeySecurity:
			ReportSetKeySecurity((PREG_SET_KEY_SECURITY_INFORMATION)Argument2);
			break;
		case RegNtPreDeleteKey:
		{
			PREG_DELETE_KEY_INFORMATION deleteInfo = (PREG_DELETE_KEY_INFORMATION)Argument2;
			if (deleteInfo != NULL)
			{
				ReportRegistryKeyEvent(PANO_EVENT_REGISTRY_DELETE_KEY, deleteInfo->Object);
			}
			break;
		}
		case RegNtPostCreateKeyEx:
			ReportCreateKey((PREG_POST_OPERATION_INFORMATION)Argument2);
			break;
		case RegNtPostLoadKey:
			ReportLoadKey((PREG_POST_OPERATION_INFORMATION)Argument2);
			break;
		case RegNtPostReplaceKey:
			ReportReplaceKey((PREG_POST_OPERATION_INFORMATION)Argument2);
			break;
		case RegNtPreRenameKey:
			BeginRenameKey((PREG_RENAME_KEY_INFORMATION)Argument2);
			break;
		case RegNtPostRenameKey:
			ReportRenameKey((PREG_POST_OPERATION_INFORMATION)Argument2);
			break;
		case RegNtPostQueryValueKey:
			ReportQueryValueKey((PREG_POST_OPERATION_INFORMATION)Argument2);
			break;
		default:
			break;
	}

	// STATUS_SUCCESS lets the registry operation proceed
	return STATUS_SUCCESS;
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

	PVOID RegistryContext = nullptr;
	status = CmRegisterCallback(RegistryCallbackFunction, RegistryContext, &g_RegistryCookie);
	if (!NT_SUCCESS(status))
	{
		NTSTATUS removeStatus = PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
		if (!NT_SUCCESS(removeStatus))
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Panoptes: Driver Failed to remove callback for Set Image Load Notify Routine Notify Routine\n");
			return removeStatus;
		}

		removeStatus = PsSetCreateProcessNotifyRoutineEx(ProcessCreateCallback, TRUE);
		if (!NT_SUCCESS(removeStatus))
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Panoptes: Driver Failed to remove callback for Set Process Creation Notify Routine Notify Routine\n");
			return removeStatus;
		}
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Panoptes: Driver Failed to Register Registry Callback, status: 0x%X\n", status);
		return status;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Set Registry Callbacks\n");


	return STATUS_SUCCESS;
}

VOID RemoveCallbacks()
{
	PsSetCreateProcessNotifyRoutineEx(ProcessCreateCallback, TRUE);
	PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
	CmUnRegisterCallback(g_RegistryCookie);

	PVOID entry;
	while ((entry = RtlGetElementGenericTableAvl(&g_ProcessList, 0)) != NULL)
	{
		RtlDeleteElementGenericTableAvl(&g_ProcessList, entry);
	}
	return;
}
