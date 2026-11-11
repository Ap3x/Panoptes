#include "panoptes_service.h"
#include "ResourceCore.h"
#include <iostream>
#include <conio.h>
#include "grpc.hpp"
#include "tray_notifications.h"
#include "error_message.h"
#include "mutex.hpp"
#include "containers.h"
#include "utils.h"
#include "database.hpp"
#include "driver.h"
#include "driver_events.h"
#include "hook_events.h"
#include "shutdown.h"
#include "Configuration.hpp"

// How long teardown waits for the gRPC server thread after shutting the server down
#define PANO_GRPC_THREAD_WAIT_MS 5000

static HANDLE g_grpcThread = NULL;

// Stops what startup started, in reverse order. Each step does nothing for a part that was
// never started, so startup failures tear down through here too
static void StopService() {
	StopHookEvents();
	// Joins the threads that queue scans, so no new scans reach the containers or the server
	StopDriverEvents();
	StopContainers();

	StopServiceServer();
	if (g_grpcThread != NULL) {
		WaitForSingleObject(g_grpcThread, PANO_GRPC_THREAD_WAIT_MS);
		CloseHandle(g_grpcThread);
		g_grpcThread = NULL;
	}

	PanoptesDatabase::CloseDatabase();
	DestroyMutex();
}

ERRORCODE CleanupWithError(ERRORCODE err) {
	StopService();
	std::string msg = GetErrorMessage(err);
	DisplayErrorMessage(msg);
	NotifyShutdownComplete();
	return err;
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	// --stop asks a running service to shut down and waits for it to exit. It shows no dialogs
	// so installers and scripts can use it. Exits 0 once the service has stopped, otherwise
	// with the error code
	if (HasCommandLineFlag("--stop")) {
		ERRORCODE stopResult = RequestServiceStop();
		return (stopResult == PANO_SUCCESS) ? 0 : stopResult;
	}

#ifndef _DEBUG
	if (IsDebuggerPresent()) {
		auto msg = GetErrorMessage(DEBUGGER);
		DisplayErrorMessage(msg);
		return DEBUGGER;
	}
#endif

#ifdef _DEBUG
	// --wait pauses before any initialization so a debugger (e.g. a KDNET kernel session)
	// can attach and set breakpoints first
	if (HasCommandLineFlag("--wait")) {
		DWORD pid = GetCurrentProcessId();
		printf("PanoptesService PID %lu (0x%lx)\n", pid, pid);
		printf("  WinDbg (kernel): !process 0x%lx 0  then  .process /i <EPROCESS>; g; .reload /user\n", pid);
		printf("Press any key to start...\n");
		_getch();
	}
#endif

	PanoptesContext serviceContext;
	serviceContext.threadError = false;
	
#pragma region Admin Check
#ifndef _DEBUG
	if (!IsRunningAsAdmin()) {
		auto msg = GetErrorMessage(NOT_ADMIN);
		DisplayErrorMessage(msg);
		return NOT_ADMIN;
	}
#endif
#pragma endregion

#pragma region Mutex Check
	if (MutexExist() != PANO_SUCCESS) {
		if (SetEnvironmentMutex() != PANO_SUCCESS) {
			auto msg = GetErrorMessage(MUTEX_SET);
			DisplayErrorMessage(msg);
			return MUTEX_SET;
		}
	}
	else {
		auto msg = GetErrorMessage(MUTEX_SET);
		DisplayErrorMessage(msg);
		return MUTEX_SET;
	}
#pragma endregion

#pragma region Shutdown Handling
	// Installed before anything starts so a shutdown requested during startup is handled once
	// startup finishes
	ERRORCODE errCode = InitializeShutdown();
	if (errCode != PANO_SUCCESS) {
		return CleanupWithError(errCode);
	}
#pragma endregion

#pragma region Panoptes Configuration
#ifdef _DEBUG
	std::string configPath = GetExecutableDirectory() + "\\panoptes.config";
#else
	std::string configPath = "C:\\ProgramData\\Panoptes\\Panoptes.config";
#endif // _DEBUG

	Configuration* configuration = new Configuration(configPath);
	try {
		configuration->Parse();
		serviceContext.config = configuration;
	}
	catch (const int& err) {
		return CleanupWithError(err);
	}
	catch (const std::exception& e) {
		// Malformed JSON or a missing or invalid setting
		std::cerr << "Failed to parse " << configPath << ": " << e.what() << std::endl;
		return CleanupWithError(INVALID_INPUT);
	}
#pragma endregion

#pragma region Database
	auto dbTmp = serviceContext.database.load();
	errCode = dbTmp.InitializeDatabase();
	if (errCode != PANO_SUCCESS) {
		return CleanupWithError(errCode);
	}
#pragma endregion

#pragma region GRPC Server
	g_grpcThread = CreateThread(
		NULL,                   // default security attributes
		0,                      // default stack size
		(LPTHREAD_START_ROUTINE)RunServiceServer,   // thread function
		&serviceContext,                   // no thread function arguments
		0,                      // default creation flags
		NULL                    // receive thread identifier
	);
	Sleep(2000);

	if (g_grpcThread == NULL || serviceContext.threadError) {
		return CleanupWithError(GRPC_SERVER_ERROR);
	}
#pragma endregion

#pragma region Container Start
#ifndef _DEBUG
	errCode = StartContainers();
	if (errCode != PANO_SUCCESS) {
		return CleanupWithError(errCode);
	}
#endif
#pragma endregion

#pragma region Detector
	// Started in every build: it dials back to the server (retrying until the port is
	// published) and receives events once the driver and hook events below start
	errCode = StartDetector();
	if (errCode != PANO_SUCCESS) {
		return CleanupWithError(errCode);
	}
#pragma endregion

#pragma region Driver
	// The driver is required and must already be running. Debug builds skip it unless
	// --driver is passed, so the service can be debugged unelevated without the driver
	bool useDriver = true;
#ifdef _DEBUG
	useDriver = HasCommandLineFlag("--driver");
#endif

	if (useDriver) {
		// The driver's device only allows SYSTEM and Administrators to open it
		if (!IsRunningAsAdmin()) {
			return CleanupWithError(NOT_ADMIN);
		}

		errCode = GetKernelServiceStatus();
		if (errCode == PANO_SERVICE_STOPPED)
		{
			// The driver is demand start: after a reboot or an MSI install it is installed but
			// not running, so start it rather than fail
			errCode = StartKernelService();
		}
		if (errCode != PANO_SERVICE_RUNNING)
		{
			return CleanupWithError(errCode);
		}

		// Always sent, even when empty, so a list left in the driver by an earlier run with a
		// different configuration is replaced
		errCode = SetInjectionExclusionsInDriver(configuration->m_dontInject);
		if (errCode != PANO_SUCCESS)
		{
			return CleanupWithError(errCode);
		}

		// Also always sent: the driver keeps the last setting until it is unloaded
		errCode = SetFileEventsInDriver(configuration->m_fileEvents);
		if (errCode != PANO_SUCCESS)
		{
			return CleanupWithError(errCode);
		}

		errCode = StartDriverEvents(configuration);
		if (errCode != PANO_SUCCESS)
		{
			return CleanupWithError(errCode);
		}
	}
#pragma endregion

#pragma region Hook Events
	// Events from the hook DLL arrive over ETW. Starting the trace session needs SYSTEM or
	// Administrators, which release builds already require for the driver; unelevated Debug
	// runs go without hook events
	if (IsRunningAsAdmin()) {
		errCode = StartHookEvents();
		if (errCode != PANO_SUCCESS)
		{
			return CleanupWithError(errCode);
		}
	}
	else {
		std::cerr << "Not running elevated: hook events will not be collected" << std::endl;
	}
#pragma endregion

	WaitForShutdownRequest();
	std::cout << "Shutting down" << std::endl;

	StopService();
	delete configuration;
	NotifyShutdownComplete();
	return 0;
}