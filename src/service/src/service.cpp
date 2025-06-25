#include "panoptes_service.h"
#include "ResourceCore.h"
#include <iostream>
#include "grpc.hpp"
#include "TrayNotifications.h"
#include "events.h"
#include "error_message.h"
#include "mutex.hpp"
#include "containers.h"
#include "utils.h"
#include "database.hpp"
#include "driver.h"
#include "Configuration.hpp"

ERRORCODE CleanupWithError(ERRORCODE err) {
	DestroyMutex();
	std::string msg = GetErrorMessage(err);
	DisplayErrorMessage(msg);
	return err;
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{

#ifndef _DEBUG
	if (IsDebuggerPresent()) {
		auto msg = GetErrorMessage(DEBUGGER);
		DisplayErrorMessage(msg);
		return DEBUGGER;
	}
#endif 

	PanoptesContext serviceContext;
	serviceContext.threadError = false;
	
#pragma region Admin Check
	if (!IsRunningAsAdmin()) {
		auto msg = GetErrorMessage(NOT_ADMIN);
		DisplayErrorMessage(msg);
		return NOT_ADMIN;
	}
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

#pragma region Panoptes Configuration
#ifdef _DEBUG
	std::string configPath = GetCurrentPath() + "\\panoptes.config";
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
#pragma endregion

#pragma region Database
	auto dbTmp = serviceContext.database.load();
	ERRORCODE errCode = dbTmp.InitializeDatabase();
	if (errCode != PANO_SUCCESS) {
		return CleanupWithError(errCode);
	}
#pragma endregion

#pragma region GRPC Server
	HANDLE grpcThread = CreateThread(
		NULL,                   // default security attributes
		0,                      // default stack size
		(LPTHREAD_START_ROUTINE)RunServiceServer,   // thread function
		&serviceContext,                   // no thread function arguments
		0,                      // default creation flags
		NULL                    // receive thread identifier
	);
	Sleep(2000);

	if (grpcThread == NULL || serviceContext.threadError) {
		return CleanupWithError(GRPC_SERVER_ERROR);
	}
#pragma endregion

#pragma region Container Start
	errCode = StartContainers(configuration->m_extensibility);
	if (errCode != PANO_SUCCESS) {
		return CleanupWithError(errCode);
	}
#pragma endregion

#pragma region ETW Trace
	HANDLE etwThread = CreateThread(
		NULL,                   					// default security attributes
		0,                      					// default stack size
		(LPTHREAD_START_ROUTINE)StartPanoptesTrace, // thread function
		&serviceContext,                   			// no thread function arguments
		0,                      					// default creation flags
		NULL                    					// receive thread identifier
	);
	Sleep(2000);
	
	if (etwThread == NULL || serviceContext.threadError){
		return CleanupWithError(START_TRACE);
	}
#pragma endregion

#pragma region Driver Check
	//Check to see if the driver is installed and running/stopped
	if (!configuration->m_ignoreDriver) {
		errCode = GetKernelServiceStatus();
		if (errCode == NOT_INSTALLED)
		{
			return CleanupWithError(errCode);
		}
		else if (errCode == PANO_SERVICE_RUNNING) {
			errCode = StopWindowsDriver();
			if (errCode != PANO_SUCCESS)
			{
				return CleanupWithError(errCode);
			}
		}
		else if (errCode == PANO_SERVICE_STOPPED) {
			errCode = StartWindowsDriver();
			if (errCode != PANO_SUCCESS)
			{
				return CleanupWithError(errCode);
			}
		}
	}
#pragma endregion

	HANDLE proc = GetCurrentProcess();
	while (1) {
		WaitForSingleObject(proc, INFINITE);
	}

	return 0;
}