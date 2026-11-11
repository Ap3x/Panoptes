#include "shutdown.h"
#include "error_message.h"
#include "mutex.hpp"
#include "utils.h"
#include <sddl.h>
#include <iostream>
#include <thread>

#pragma comment(lib, "advapi32.lib")

// Session-local, like the service mutex, so "--stop" works from the session the service was
// started in
#define PANO_STOP_EVENT_NAME L"PanoptesStop"

// How long --stop waits for the service to exit after setting its stop event
#define PANO_STOP_EXIT_WAIT_MS 15000

#define PANO_SHUTDOWN_WINDOW_CLASS L"PanoptesShutdownWindow"

static HANDLE g_StopEvent = NULL;
static HANDLE g_ShutdownComplete = NULL;

static void RequestShutdown()
{
	if (g_StopEvent != NULL)
	{
		SetEvent(g_StopEvent);
	}
}

// Requests shutdown and holds off the end of the process until teardown has finished
static void RequestShutdownAndWait()
{
	RequestShutdown();
	WaitForSingleObject(g_ShutdownComplete, PANO_SHUTDOWN_WAIT_MS);
}

#pragma region Console Handler

static BOOL WINAPI ConsoleHandler(DWORD controlType)
{
	switch (controlType)
	{
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
		// The process keeps running after these return, so there is nothing to wait for
		RequestShutdown();
		return TRUE;
	case CTRL_CLOSE_EVENT:
	case CTRL_LOGOFF_EVENT:
	case CTRL_SHUTDOWN_EVENT:
		RequestShutdownAndWait();
		return TRUE;
	default:
		return FALSE;
	}
}

#pragma endregion

#pragma region Session End Window

static LRESULT CALLBACK ShutdownWindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_QUERYENDSESSION:
		return TRUE;
	case WM_ENDSESSION:
		// wParam is FALSE when the session end was cancelled
		if (wParam)
		{
			RequestShutdownAndWait();
		}
		return 0;
	default:
		return DefWindowProcW(window, message, wParam, lParam);
	}
}

// Owns the hidden window and pumps its messages for the life of the process. The window is
// top-level rather than message-only because message-only windows do not receive the
// WM_QUERYENDSESSION and WM_ENDSESSION broadcasts
static void ShutdownWindowThread(HANDLE ready, HWND *created)
{
	HINSTANCE instance = GetModuleHandleW(NULL);

	WNDCLASSW windowClass{};
	windowClass.lpfnWndProc = ShutdownWindowProc;
	windowClass.hInstance = instance;
	windowClass.lpszClassName = PANO_SHUTDOWN_WINDOW_CLASS;
	RegisterClassW(&windowClass);

	// Never shown
	*created = CreateWindowExW(0, PANO_SHUTDOWN_WINDOW_CLASS, L"Panoptes", 0,
		0, 0, 0, 0, NULL, NULL, instance, NULL);
	SetEvent(ready);
	if (*created == NULL)
	{
		return;
	}

	MSG message;
	while (GetMessageW(&message, NULL, 0, 0) > 0)
	{
		TranslateMessage(&message);
		DispatchMessageW(&message);
	}
}

#pragma endregion

ERRORCODE InitializeShutdown()
{
	// Elevated, the event is restricted to SYSTEM and Administrators so an unelevated process
	// cannot stop the service. Unelevated Debug runs use the default security so --stop still
	// works from the same user
	SECURITY_ATTRIBUTES security{ sizeof(security), NULL, FALSE };
	PSECURITY_DESCRIPTOR descriptor = NULL;
	if (IsRunningAsAdmin())
	{
		if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)",
			SDDL_REVISION_1, &descriptor, NULL))
		{
			return WINDOWS_ERR;
		}
		security.lpSecurityDescriptor = descriptor;
	}

	g_StopEvent = CreateEventW(&security, TRUE, FALSE, PANO_STOP_EVENT_NAME);
	DWORD error = GetLastError();
	if (descriptor != NULL)
	{
		LocalFree(descriptor);
	}
	if (g_StopEvent == NULL)
	{
		std::cerr << "Failed to create the stop event. Error code: " << error << std::endl;
		return WINDOWS_ERR;
	}
	if (error == ERROR_ALREADY_EXISTS)
	{
		// Named objects disappear with their last handle, so another process is holding one
		// with this name, possibly to stop the service through it. Do not use it
		std::cerr << "The stop event already exists in another process" << std::endl;
		CloseHandle(g_StopEvent);
		g_StopEvent = NULL;
		return WINDOWS_ERR;
	}

	g_ShutdownComplete = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (g_ShutdownComplete == NULL)
	{
		return WINDOWS_ERR;
	}

	SetConsoleCtrlHandler(ConsoleHandler, TRUE);

	HANDLE ready = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (ready == NULL)
	{
		return WINDOWS_ERR;
	}
	HWND window = NULL;
	std::thread(ShutdownWindowThread, ready, &window).detach();
	WaitForSingleObject(ready, INFINITE);
	CloseHandle(ready);

	if (window == NULL)
	{
		std::cerr << "Failed to create the session end window" << std::endl;
		return WINDOWS_ERR;
	}

	return PANO_SUCCESS;
}

void WaitForShutdownRequest()
{
	WaitForSingleObject(g_StopEvent, INFINITE);
}

void NotifyShutdownComplete()
{
	if (g_ShutdownComplete != NULL)
	{
		SetEvent(g_ShutdownComplete);
	}
}

ERRORCODE RequestServiceStop()
{
	HANDLE stopEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, PANO_STOP_EVENT_NAME);
	if (stopEvent == NULL)
	{
		DWORD error = GetLastError();
		if (error == ERROR_ACCESS_DENIED)
		{
			return NOT_ADMIN;
		}
		std::cerr << "Panoptes is not running" << std::endl;
		return WINDOWS_ERR;
	}

	SetEvent(stopEvent);
	CloseHandle(stopEvent);

	// The service holds the mutex until the end of its teardown
	ULONGLONG deadline = GetTickCount64() + PANO_STOP_EXIT_WAIT_MS;
	while (GetTickCount64() < deadline)
	{
		HANDLE mutex = OpenMutexA(SYNCHRONIZE, FALSE, SERVICE_MUTEX);
		if (mutex == NULL)
		{
			return PANO_SUCCESS;
		}
		CloseHandle(mutex);
		Sleep(100);
	}

	std::cerr << "Panoptes did not stop within " << PANO_STOP_EXIT_WAIT_MS / 1000 << " seconds" << std::endl;
	return WINDOWS_ERR;
}
