#include "utils.h"

BOOLEAN Is64BitProcess(PEPROCESS targetProcess) {
	UINT64* processAsUint64 = reinterpret_cast<UINT64*>(targetProcess);
	PVOID* wow64ProcessPtr = reinterpret_cast<PVOID*>(processAsUint64 + 0x580 / sizeof(UINT64));
	if (*wow64ProcessPtr == NULL)
	{
		return TRUE;
	}
	return FALSE;
}

NTSTATUS GetFileNameFromPath(PUNICODE_STRING FullPath, PUNICODE_STRING FileName) {
	USHORT i;
	USHORT lengthInChars;

	if (!FullPath || !FileName || !FullPath->Buffer || FullPath->Length == 0) {
		return STATUS_INVALID_PARAMETER;
	}

	lengthInChars = FullPath->Length / sizeof(WCHAR);

	// Search backwards for the last backslash
	for (i = lengthInChars; i > 0; i--) {
		if (FullPath->Buffer[i - 1] == L'\\') {
			break;
		}
	}

	// Set up the filename UNICODE_STRING (points to existing buffer)
	FileName->Buffer = &FullPath->Buffer[i];
	FileName->Length = (lengthInChars - i) * sizeof(WCHAR);
	FileName->MaximumLength = FileName->Length;

	return STATUS_SUCCESS;
}

NTSTATUS QueryProcessMitigationPolicy(HANDLE ProcessId, PROCESS_MITIGATION_POLICY_INFORMATION* policyInfo) {
	UNREFERENCED_PARAMETER(policyInfo);
	HANDLE hProcess;
	PEPROCESS eProcess;

	if (ProcessId == NULL) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Panoptes: Invalid ProcessId\n");
		return STATUS_INVALID_PARAMETER; //0xC000000D
	}

	NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &eProcess);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Panoptes: PsLookupProcessByProcessId failed with status 0x%X\n", status);
		return status;
	}

	status = ObOpenObjectByPointer(
		eProcess,
		OBJ_KERNEL_HANDLE,
		NULL,
		0x1000,//PROCESS_QUERY_LIMITED_INFORMATION,
		*PsProcessType,
		KernelMode,
		&hProcess);

	ObDereferenceObject(eProcess);

	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Panoptes: ObOpenObjectByPointer failed with status 0x%X\n", status);
		return status;
	}

	PROCESS_MITIGATION_POLICY_INFORMATION policyInfoLocal;
	policyInfoLocal.Policy = ProcessSignaturePolicy;
	status = ZwQueryInformationProcess(hProcess, ProcessMitigationPolicy, &policyInfoLocal, sizeof(policyInfoLocal), nullptr);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Panoptes: ZwQueryInformationProcess failed with status 0x%X\n", status);
	}

	if (&policyInfoLocal != NULL) {
		if (policyInfoLocal.Data.SignaturePolicy.MicrosoftSignedOnly != 0) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Process with MicrosoftOnly");
		}
	}

	ZwClose(hProcess);

	return STATUS_SUCCESS;
}

PVOID NTAPI RtlxFindExportedRoutineByName(_In_ PVOID DllBase, _In_ PANSI_STRING ExportName) {
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
