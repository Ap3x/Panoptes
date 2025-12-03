#pragma once
#include "pch.h"
#include "state.h"

EXTERN_C BOOLEAN NTAPI PsIsProtectedProcess(_In_ PEPROCESS Process);

VOID RemoveCallbacks();
NTSTATUS InitializeKernelCallbacks(PanoptesState* State);
