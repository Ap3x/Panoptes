#pragma once
#include <ntifs.h>

/// @brief Initializes the (empty) list of image names the hook DLL is not injected into. Call
/// before the device is created, since IOCTL_PANOPTES_SET_INJECTION_EXCLUSIONS replaces it
void InjectExclusionsInit();

/// @brief Frees the list. Call once the device and the image load callback are gone
void InjectExclusionsCleanup();

/// @brief Replaces the list with the names in a PANO_INJECTION_EXCLUSIONS
/// @param Buffer The IOCTL_PANOPTES_SET_INJECTION_EXCLUSIONS input buffer
/// @param Length The size of Buffer in bytes
/// @return STATUS_INVALID_PARAMETER if the buffer is malformed, in which case the list is unchanged
NTSTATUS InjectExclusionsSet(_In_reads_bytes_(Length) PVOID Buffer, _In_ ULONG Length);

/// @brief Checks whether a process's image is in the list. PASSIVE_LEVEL only
/// @param ProcessImagePath The process's NT image path, e.g. from SeLocateProcessImageName.
/// Full-path entries are compared with the whole path and file-name entries with the part after
/// the last \, both without regard to case. Entries may use * (any characters, \ included) and ?
BOOLEAN IsInjectionExcluded(_In_ PCUNICODE_STRING ProcessImagePath);
