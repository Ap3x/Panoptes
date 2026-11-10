#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include "service_constants.h"

ERRORCODE GetKernelServiceStatus();

/// @brief Asks the driver to terminate a process (IOCTL_PANOPTES_TERMINATE_PROCESS)
/// @param processId The ID of the process to terminate
/// @return PANO_SUCCESS if the process was terminated, otherwise an error code
ERRORCODE TerminateProcessByDriver(UINT64 processId);

/// @brief Replaces the driver's list of process image names it does not inject the hook DLL
/// into (IOCTL_PANOPTES_SET_INJECTION_EXCLUSIONS). An empty list clears it
/// @param imageNames The DontInject setting (UTF-8): file names such as "msedge.exe" or full
/// paths such as "C:\Tools\app.exe". Paths are converted to NT paths for the driver
/// @return PANO_SUCCESS if the driver accepted the list, INVALID_INPUT if an entry is too long,
/// is on a drive that does not exist, or there are too many, otherwise an error code
ERRORCODE SetInjectionExclusionsInDriver(const std::vector<std::string>& imageNames);

/// @brief Tells the driver which groups of file system events to report
/// (IOCTL_PANOPTES_SET_FILE_EVENTS)
/// @param groups The FileEvents setting: names from Configuration::FileEventNames()
/// @return PANO_SUCCESS if the driver accepted them, INVALID_INPUT for an unknown name,
/// otherwise an error code
ERRORCODE SetFileEventsInDriver(const std::vector<std::string>& groups);
