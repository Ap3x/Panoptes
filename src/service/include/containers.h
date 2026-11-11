#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <panoptes.pb.h>
#include "service_constants.h"
#include "Configuration.hpp"

ERRORCODE StartContainers();

/// @brief Ends every container started by StartContainers. Safe to call if none were started
void StopContainers();

/// @brief Starts PanoptesDetector.exe from the service's folder with the rules in its rules
/// subfolder, in the same job as the containers so it ends with the service. Does nothing (and
/// succeeds) when the detector is not installed
ERRORCODE StartDetector();

/// @brief The path the service starts the detector from: PanoptesDetector.exe in the service's
/// folder. Only a process running this file may use the detector RPCs
std::wstring DetectorExecutablePath();

/// @brief Whether a process is one the service started (a container or the detector)
/// @param process A handle with PROCESS_QUERY_LIMITED_INFORMATION access
bool IsServiceChildProcess(HANDLE process);
