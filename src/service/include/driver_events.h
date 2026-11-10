#pragma once
#include <Windows.h>
#include "service_constants.h"
#include "Configuration.hpp"

/// @brief Opens the Panoptes driver device and starts the threads that read events from it
/// (IOCTL_PANOPTES_GET_EVENT) and queue scans for files that were created or written.
/// @param configuration The service configuration; its log exclusions are applied to events
/// @return PANO_SUCCESS if the device was opened and the reader started, otherwise an error code
ERRORCODE StartDriverEvents(const Configuration* configuration);

/// @brief Cancels the pending event requests and stops the reader threads
void StopDriverEvents();
