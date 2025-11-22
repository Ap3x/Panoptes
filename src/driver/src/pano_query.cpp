#include "pano_query.h" 
#include <ntifs.h>

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