#pragma once
#include <Windows.h>
#include "service_constants.h"

// Shutdown requests reach the service in three ways, all of which set the same stop event:
//  - Ctrl+C, Ctrl+Break or closing the console (Debug builds run as a console program)
//  - The user logging off or Windows shutting down, delivered to a hidden top-level window as
//    WM_ENDSESSION
//  - "PanoptesService.exe --stop", which sets the named stop event from another process
//
// Windows ends the process as soon as a console control handler or WM_ENDSESSION returns, so
// those wait (up to PANO_SHUTDOWN_WAIT_MS) for the main thread to report that it has finished
// tearing the service down.

#define PANO_SHUTDOWN_WAIT_MS 10000

/// @brief Creates the stop event and installs the console handler and session-end window.
/// The stop event can only be opened by SYSTEM and Administrators when the service runs
/// elevated. Fails if another process already holds an object with the event's name.
/// @return PANO_SUCCESS, or WINDOWS_ERR if the event or window could not be created
ERRORCODE InitializeShutdown();

/// @brief Blocks until a shutdown is requested
void WaitForShutdownRequest();

/// @brief Tells console handlers and the session-end window that teardown has finished, so
/// they can return and let Windows end the process
void NotifyShutdownComplete();

/// @brief Implements --stop: sets a running service's stop event and waits for it to exit
/// @return PANO_SUCCESS once the service has exited, NOT_ADMIN if the event could not be
/// opened for lack of rights, or WINDOWS_ERR if no service is running or it did not exit in time
ERRORCODE RequestServiceStop();
