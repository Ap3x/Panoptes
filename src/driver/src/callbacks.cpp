#include "callbacks.h"
#include "state.h"
#include "inject.h"
#include "utils.h"

PanoptesState g_State{};

PPANO_PROCESS_INFO GetProcessInfo(HANDLE ProcessId)
{
	auto pi = (PPANO_PROCESS_INFO)RtlLookupElementGenericTableAvl(&g_State.Processes, &ProcessId);
	if (pi != nullptr) {
		return pi;
	}
	return nullptr;
}

VOID RemoveProcessInfo(HANDLE ProcessId) {
	ExAcquireFastMutex(&g_State.ProcessesLock);
	PANO_PROCESS_INFO pi;
	pi.ProcessId = HandleToUlong(ProcessId);
	RtlDeleteElementGenericTableAvl(&g_State.Processes, &pi);
	KdPrint((PANOPTES_PREFIX_SUCCESS "Process %u deleted from table\n", pi.ProcessId));
	ExReleaseFastMutex(&g_State.ProcessesLock);
	return;
}

// https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/windows-kernel-mode-process-and-thread-manager#best
// This callback is ran in PASSIVE_LEVEL IRQL, but with safe mode enabled so no actions that would lock this function and prevent the image from loading like mutexes
VOID LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
	UNREFERENCED_PARAMETER(ImageInfo);
	ULONG id = HandleToUlong(ProcessId);

	if (PsIsProtectedProcess(PsGetCurrentProcess())){
		KdPrint((PANOPTES_PREFIX_WARNING "Skipping protected process %u\n", id));
		RemoveProcessInfo(ProcessId);
		return;
	}

	UNICODE_STRING loadedImageName{};
	GetFileNameFromPath(FullImageName, &loadedImageName);

	auto pi = GetProcessInfo(ProcessId);
	if (pi == nullptr) {
		return;
	}

	if (pi->kernel32Loaded && pi->kernelBaseLoaded && pi->ntdllLoaded) {
		if (pi->Injected) {
			return;
		}
		KdPrint((PANOPTES_PREFIX_SUCCESS "All required images loaded for process %u, attempting injection\n", id));
		auto test = g_State.ImageBase;
		InstallKernelModeApcToInjectDll(ProcessId, test);
		pi->Injected = TRUE;
		return;
	}

	UNICODE_STRING ntdllLoadImage;
	RtlInitUnicodeString(&ntdllLoadImage, L"ntdll.dll");
	if (RtlCompareUnicodeString(&ntdllLoadImage, &loadedImageName, TRUE) == 0) {
		pi->ntdllLoaded = TRUE;
	}

	UNICODE_STRING kernel32LoadImage;
	RtlInitUnicodeString(&kernel32LoadImage, L"kernel32.dll");
	if (RtlCompareUnicodeString(&kernel32LoadImage, &loadedImageName, TRUE) == 0) {
		PVOID ImageBaseValue = g_State.ImageBase;
		if (ImageBaseValue == nullptr) {
			return;
		}
		RtlCopyMemory(g_State.ImageBase, &ImageInfo->ImageBase, sizeof(PVOID));
		pi->kernel32Loaded = TRUE;
	}

	UNICODE_STRING kernelbaseLoadImage;
	RtlInitUnicodeString(&kernel32LoadImage, L"kernelbase.dll");
	if (RtlCompareUnicodeString(&kernel32LoadImage, &loadedImageName, TRUE) == 0) {
		KdPrint((PANOPTES_PREFIX_SUCCESS "Attempting to injected Into %u\n", id));
		pi->kernelBaseLoaded = TRUE;
	}

	return;
}

_Use_decl_annotations_
VOID ProcessCreateCallback(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
	UNREFERENCED_PARAMETER(Process);
	ULONG id = HandleToUlong(ProcessId);

	if (CreateInfo != NULL) {
		ExAcquireFastMutex(&g_State.ProcessesLock);
		//Check if process info already exists
		auto pi = (PPANO_PROCESS_INFO)RtlLookupElementGenericTableAvl(&g_State.Processes, &id);
		if (pi == nullptr) {
			PANO_PROCESS_INFO newProcessEntry{};
			newProcessEntry.ProcessId = id;
			pi = (PPANO_PROCESS_INFO)RtlInsertElementGenericTableAvl(&g_State.Processes, &newProcessEntry, sizeof(newProcessEntry), nullptr);
			KdPrint((PANOPTES_PREFIX_SUCCESS "Process %u added to table\n", id));
		}
		ExReleaseFastMutex(&g_State.ProcessesLock);
	}
	else {
		RemoveProcessInfo(&id);
		KdPrint((PANOPTES_PREFIX_SUCCESS "Process %u terminated and removed from table\n", id));
	}
}

NTSTATUS InitializeKernelCallbacks() {
	PAGED_CODE();
	NTSTATUS status;

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
	status = g_State.Init();

	return STATUS_SUCCESS;
}

VOID RemoveCallbacks() {
	PsSetCreateProcessNotifyRoutineEx(ProcessCreateCallback, TRUE);
	PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
	g_State.Term();
	return;
}
