#pragma once
#include <Windows.h>
#include <string>

// Image paths of processes, remembered from the driver's process events.
//
// Hook events reach the service about a second after they happen, often after the process
// that raised them has exited, so asking Windows for the image by PID at that point fails (or,
// once the PID is reused, names the wrong program). The driver's ProcessCreated arrives first,
// so the service records each image there and looks it up by PID and event time instead.
// Entries are kept for a while after the process exits, for events still on their way.

/// @brief Records a process start (ProcessCreated)
/// @param image The image path as the driver reports it. "\??\C:\..." and "\SystemRoot\..."
/// are converted to "C:\..." paths
/// @param time When the process was created
void RecordProcessStart(DWORD processId, const std::string& image, const FILETIME& time);

/// @brief Records a process exit (ProcessTerminated). Its entry is forgotten a minute later
void RecordProcessExit(DWORD processId);

/// @brief The image of the process that had processId at the given time, from the recorded
/// starts. Empty if the service did not see that process start (e.g. it started before the
/// service)
std::string LookupProcessImage(DWORD processId, const FILETIME& time);

/// @brief LookupProcessImage, falling back to asking Windows (QueryFullProcessImageName) for
/// processes the service did not see start. Empty if both fail
std::string ResolveProcessImage(DWORD processId, const FILETIME& time);
