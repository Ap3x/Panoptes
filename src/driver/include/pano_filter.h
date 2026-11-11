#pragma once
#include <fltKernel.h>

NTSTATUS FilterInit(PDRIVER_OBJECT* DriverObject);

/// @brief Unregisters the minifilter if FilterInit registered it
void FilterUninit();

/// @brief Sets which PANO_FILE_EVENT_GROUP bits are reported (IOCTL_PANOPTES_SET_FILE_EVENTS)
/// @param Buffer A PANO_FILE_EVENTS
/// @param Length The size of Buffer in bytes
/// @return STATUS_INVALID_PARAMETER if the buffer is too small or sets unknown bits
NTSTATUS FilterSetFileEvents(_In_reads_bytes_(Length) PVOID Buffer, _In_ ULONG Length);
