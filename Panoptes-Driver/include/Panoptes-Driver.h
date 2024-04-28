#pragma once
#include <ntifs.h>

//NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);

void UnloadDriver(PDRIVER_OBJECT pDriverObject);

void NotifyProcesses(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);

VOID PipeThreadFunction(PVOID Context);

void KillProcess(HANDLE processHandle);

