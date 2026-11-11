#pragma once
#include <Windows.h>
#include "service_constants.h"

/// @brief Starts a real-time ETW session for the hook DLL's "Panoptes.Hook" TraceLogging
/// provider and a thread that logs each event it delivers. A session left behind by a previous
/// run of the service is stopped and replaced. Requires SYSTEM or Administrators.
/// @return PANO_SUCCESS if the session was started and is being consumed, otherwise an error code
ERRORCODE StartHookEvents();

/// @brief Stops the ETW session and waits for the consumer thread to deliver what it buffered
void StopHookEvents();
