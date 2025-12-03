#include "pch.h"
#include "state.h"

NTSTATUS PanoptesState::Init() {
	ExInitializeFastMutex(&ProcessesLock);
	RtlInitializeGenericTableAvl(&Processes, ProcessCompare, TableAlloc, TableFree, this);
	return STATUS_SUCCESS;
}

RTL_GENERIC_COMPARE_RESULTS PanoptesState::ProcessCompare(PRTL_AVL_TABLE Table, PVOID FirstStruct, PVOID SecondStruct) {
	UNREFERENCED_PARAMETER(Table);

	auto p1 = (PPANO_PROCESS_INFO)FirstStruct;
	auto p2 = (PPANO_PROCESS_INFO)SecondStruct;
	if (p1->ProcessId == p2->ProcessId)
		return GenericEqual;

	return p1->ProcessId > p2->ProcessId ? GenericGreaterThan : GenericLessThan;
}

_Use_decl_annotations_
PVOID PanoptesState::TableAlloc(_RTL_AVL_TABLE* Table, CLONG ByteSize) {
	UNREFERENCED_PARAMETER(Table);
	return ExAllocatePool2(POOL_FLAG_PAGED, ByteSize, 'stky');
}

_Use_decl_annotations_
VOID PanoptesState::TableFree(_RTL_AVL_TABLE* Table, PVOID Buffer) {
	UNREFERENCED_PARAMETER(Table);
	ExFreePoolWithTag(Buffer, 'stky');
}

void PanoptesState::Term() {
	// Delete all elements by repeatedly deleting the first element until table is empty
	// This is safer than enumerating and deleting, as deletion may invalidate enumeration state
	PVOID element;
	while ((element = RtlEnumerateGenericTableAvl(&Processes, TRUE)) != nullptr) {
		RtlDeleteElementGenericTableAvl(&Processes, element);
	}
}