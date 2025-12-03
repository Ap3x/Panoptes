#include "callbacks.h"
#include "inject.h"
#include "utils.h"
#include <ntifs.h>
PanoptesState* g_pState = nullptr;

PPANO_PROCESS_INFO GetProcessInfo(HANDLE ProcessId) {
	ULONG id = HandleToUlong(ProcessId);
	auto pi = (PPANO_PROCESS_INFO)RtlLookupElementGenericTableAvl(&g_pState->Processes, &id);
	if (pi != nullptr) {
		return pi;
	}
	return nullptr;
}

// https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/windows-kernel-mode-process-and-thread-manager#best
// This callback is ran in PASSIVE_LEVEL IRQL, but with safe mode enabled so no actions that would lock this function and prevent the image from loading like mutexes
VOID LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
	UNREFERENCED_PARAMETER(ImageInfo);
	ULONG id = HandleToUlong(ProcessId);

	PPANO_PROCESS_INFO pi = GetProcessInfo(ProcessId);
	if (pi == nullptr) {
		return;
	}

	if (pi->Injected || pi->MitigationPolicyBan) {
		return;
	}

	UNICODE_STRING loadedImageName{};
	GetFileNameFromPath(FullImageName, &loadedImageName);

	// NTDLL must be loaded for the hooks to work
	if (!pi->NtdllLoaded) {
		UNICODE_STRING ntdllLoadImage;
		RtlInitUnicodeString(&ntdllLoadImage, L"ntdll.dll");
		if (RtlCompareUnicodeString(&ntdllLoadImage, &loadedImageName, TRUE) == 0) {
			pi->NtdllLoaded = TRUE;

			PEPROCESS targetProcess{};
			NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &targetProcess);
			if (!NT_SUCCESS(status)) {
				return;
			}

			PROCESS_MITIGATION_POLICY_INFORMATION policyInfo;
			policyInfo.Policy = ProcessSignaturePolicy;

			status = QueryProcessMitigationPolicy(targetProcess, &policyInfo);
			if (!NT_SUCCESS(status)) {
				ObDereferenceObject(targetProcess);
				return;
			}

			if (policyInfo.Data.SignaturePolicy.MicrosoftSignedOnly != 0 ||
				policyInfo.Data.SignaturePolicy.StoreSignedOnly != 0 ||
				policyInfo.Data.SignaturePolicy.MitigationOptIn != 0) {
				pi->MitigationPolicyBan = TRUE;
				ObDereferenceObject(targetProcess);
				return;
			}

			ObDereferenceObject(targetProcess);
		}
	}
	
	if (!pi->Wow64Loaded) {
		//Check if x86 process and ensure that it will be ready to be injected into
		UNICODE_STRING ntdllLoadImage;
		RtlInitUnicodeString(&ntdllLoadImage, L"wow64.dll");
		if (RtlCompareUnicodeString(&ntdllLoadImage, &loadedImageName, TRUE) == 0) {
			pi->Wow64Loaded = TRUE;
			return;
		}
	}
	
	if (!pi->Kernel32Loaded) {
		// Kernel32 and KernelBase must be loaded for the inject to work
		UNICODE_STRING kernel32LoadImage;
		RtlInitUnicodeString(&kernel32LoadImage, L"kernel32.dll");
		if (RtlCompareUnicodeString(&kernel32LoadImage, &loadedImageName, TRUE) == 0) {
			pi->Kernel32Loaded = TRUE;
			pi->Kernel32ImageBase = ImageInfo->ImageBase;
			return;
		}
	}

	if (!pi->KernelBaseLoaded) {
		// Kernel32 and KernelBase must be loaded for the inject to work
		UNICODE_STRING kernelbaseLoadImage;
		RtlInitUnicodeString(&kernelbaseLoadImage, L"kernelbase.dll");
		if (RtlCompareUnicodeString(&kernelbaseLoadImage, &loadedImageName, TRUE) == 0) {
			pi->KernelBaseLoaded = TRUE;
			return;
		}
	}

	if (pi->Kernel32Loaded && pi->KernelBaseLoaded) {
		if (pi->Kernel32ImageBase != nullptr) {
			pi->Injected = TRUE;
			InstallKernelModeApcToInjectDll(ProcessId, &pi->Kernel32ImageBase, pi->Wow64Loaded);
		}
	}

	return;
}

NTSTATUS IsIgnoredExecutable(ULONG* ProcessId, BOOLEAN* result) {
	PEPROCESS targetProcess{};
	NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &targetProcess);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	PUNICODE_STRING processPath = NULL;
	status = SeLocateProcessImageName(targetProcess, &processPath);
	if (!NT_SUCCESS(status)) {
		ObDereferenceObject(targetProcess);
		return status;
	}

	UNICODE_STRING processPathFile{};
	GetFileNameFromPath(processPath, &processPathFile);

	UNICODE_STRING ignore1;
	UNICODE_STRING ignore2;
	UNICODE_STRING ignore3;
	UNICODE_STRING ignore4;
	UNICODE_STRING ignore5;
	UNICODE_STRING ignore6;
	UNICODE_STRING ignore7;
	RtlInitUnicodeString(&ignore1, L"\\Device\\HarddiskVolume3\\Windows\\System32\\dllhost.exe");
	// Windows Update Binary
	RtlInitUnicodeString(&ignore2, L"\\Device\\HarddiskVolume3\\Windows\\System32\\mousocoreworker.exe");
	RtlInitUnicodeString(&ignore3, L"\\Device\\HarddiskVolume3\\Windows\\System32\\USOCoreWorker.exe");
	RtlInitUnicodeString(&ignore4, L"\\Device\\HarddiskVolume3\\Windows\\System32\\USOClient.exe");

	RtlInitUnicodeString(&ignore5, L"msedgewebview2.exe");
	RtlInitUnicodeString(&ignore6, L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\WerFault.exe");
	RtlInitUnicodeString(&ignore7, L"\\Device\\HarddiskVolume3\\Windows\\System32\\WerFault.exe");

	if (RtlEqualUnicodeString(&processPathFile, &ignore5, TRUE)) {
		ExFreePool(processPath);
		ObDereferenceObject(targetProcess);
		return STATUS_UNSUCCESSFUL;
	}

	if (RtlEqualUnicodeString(processPath, &ignore1, TRUE) ||
		RtlEqualUnicodeString(processPath, &ignore2, TRUE) ||
		RtlEqualUnicodeString(processPath, &ignore3, TRUE) ||
		RtlEqualUnicodeString(processPath, &ignore4, TRUE) ||
		RtlEqualUnicodeString(processPath, &ignore6, TRUE) ||
		RtlEqualUnicodeString(processPath, &ignore7, TRUE)
		) {
		ExFreePool(processPath);
		ObDereferenceObject(targetProcess);
		*result = true;
		return STATUS_SUCCESS;
	}

	ObDereferenceObject(targetProcess);
	*result = false ;
	return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID ProcessCreateCallback(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
	UNREFERENCED_PARAMETER(Process);
	ULONG id = HandleToUlong(ProcessId);

	if (CreateInfo != NULL) {
		if (PsIsProtectedProcess(PsGetCurrentProcess())) {
			return;
		}

		ExAcquireFastMutex(&g_pState->ProcessesLock);
		auto pi = (PPANO_PROCESS_INFO)RtlLookupElementGenericTableAvl(&g_pState->Processes, &id);
		if (pi == nullptr) {
			BOOLEAN ignored = false;
			IsIgnoredExecutable(&id, &ignored);

			PANO_PROCESS_INFO newProcessEntry{};
			newProcessEntry.ProcessId = id;
			BOOLEAN successInsert = false;
			
			pi = (PPANO_PROCESS_INFO)RtlInsertElementGenericTableAvl(&g_pState->Processes, &newProcessEntry, sizeof(newProcessEntry), &successInsert);
			if (!successInsert) {
				KdPrint((PANOPTES_PREFIX_ERROR "Error inserting process into AVL tree\n"));
			}
		}
		ExReleaseFastMutex(&g_pState->ProcessesLock);
	}
	else {
		ExAcquireFastMutex(&g_pState->ProcessesLock);
		RtlDeleteElementGenericTableAvl(&g_pState->Processes, &id);
		ExReleaseFastMutex(&g_pState->ProcessesLock);
	}
}

NTSTATUS InitializeKernelCallbacks(PanoptesState* State) {
	PAGED_CODE();
	NTSTATUS status;

	g_pState = State;

	status = PsSetCreateProcessNotifyRoutineEx(ProcessCreateCallback, FALSE);
	if (!NT_SUCCESS(status)) {
		KdPrint((PANOPTES_PREFIX_ERROR "Driver Failed to Set Process Creation Notify Routine Notify Routine - Ensure /INTEGRITYCHECK is added to the linker options\n"));
		return status;
	}
	KdPrint((PANOPTES_PREFIX_SUCCESS "Set Process Creation Notify Callbacks\n"));

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
