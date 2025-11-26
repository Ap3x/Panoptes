#pragma once
#include "pch.h"

EXTERN_C BOOLEAN NTAPI PsIsProtectedProcess(_In_ PEPROCESS Process);

VOID RemoveCallbacks();
NTSTATUS InitializeKernelCallbacks();
