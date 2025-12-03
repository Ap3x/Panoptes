#include "utils.h"

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

NTSTATUS QueryProcessMitigationPolicy(PEPROCESS Process, PROCESS_MITIGATION_POLICY_INFORMATION* policyInfo) {
	HANDLE hProcess;

	NTSTATUS status = ObOpenObjectByPointer(
		Process,
		OBJ_KERNEL_HANDLE,
		NULL,
		0x1000,//PROCESS_QUERY_LIMITED_INFORMATION,
		*PsProcessType,
		KernelMode,
		&hProcess);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = ZwQueryInformationProcess(
		hProcess, 
		ProcessMitigationPolicy, 
		policyInfo, 
		sizeof(PROCESS_MITIGATION_POLICY_INFORMATION), 
		nullptr);
	ZwClose(hProcess);

	return status;
}

