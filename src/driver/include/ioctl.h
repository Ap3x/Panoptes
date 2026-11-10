#pragma once
#include <ntifs.h>
#include "pano_events.h"

/// @brief Creates the \Device\Panoptes device and symbolic link and registers the IOCTL dispatch routines
NTSTATUS InitializeDriverLink(PDRIVER_OBJECT DriverObject);

/// @brief Deletes the device and symbolic link created by InitializeDriverLink
void RemoveDriverLink();
