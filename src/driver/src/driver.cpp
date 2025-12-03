#include "pch.h"
#include "callbacks.h"
#include "trace.h"
#include "filter.h"
#include "state.h"

PanoptesState g_State{};

void UnloadPanoptes(PDRIVER_OBJECT DriverObject) {
	PAGED_CODE();
	
	// Remove callbacks first to prevent new accesses to state
	RemoveCallbacks();
	
	FltUnregisterFilter(g_State.FilterHandle);
	
	// Now safe to clean up state - no callbacks can access it
	g_State.Term();
	
	Log_DriverExit(DriverObject);
	
	TraceTerminate();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT  DriverObject,PUNICODE_STRING RegistryPath) {
	PAGED_CODE();
	NTSTATUS status = NULL;
	DriverObject->DriverUnload = UnloadPanoptes;
	
	status = g_State.Init();
	if (!NT_SUCCESS(status)) {
		KdPrint(( PANOPTES_PREFIX_ERROR "An error occured when attempting to initialize global state\n"));
		return status;
	}

	TraceInitialize();

	Log_DriverEntry(DriverObject, RegistryPath);

	status = FilterInitialize(DriverObject, &g_State);
	if (!NT_SUCCESS(status)) {
		KdPrint(( PANOPTES_PREFIX_ERROR "An error occured when attempting to initialized filter\n"));
		return status;
	}

	//status = InitializeDriverLink(DriverObject);
	//if (!NT_SUCCESS(status))
	//{
	//	KdPrint(( PANOPTES_PREFIX_ERROR "An error occured when attempting to initialized device pipe\n"));
	//	return status;
	//}

	status = InitializeKernelCallbacks(&g_State);
	if (!NT_SUCCESS(status))
	{
		KdPrint(( PANOPTES_PREFIX_ERROR "An error occured when attempting to initialized kernel callbacks\n"));
		return status;
	}

	return 0;
}
