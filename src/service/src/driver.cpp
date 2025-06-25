#include "driver.h"
#include "error_message.h"

ERRORCODE GetKernelServiceStatus()
{
	SC_HANDLE serviceControlManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (serviceControlManager == NULL) {
		//cout << "Failed to open Service Control Manager. Error code: " << GetLastError() << endl;
		return NOT_SET;
	}

	// Open the service
	SC_HANDLE service = OpenServiceA(serviceControlManager, KERNEL_DRIVER_SERVICE_NAME, SERVICE_INTERROGATE);
	if (service == NULL) {
		//string message = format("Failed to open and stop the service. Error code: {}", GetLastError());
		//LogErrorMessage(message);

		CloseServiceHandle(serviceControlManager);
		return NOT_INSTALLED;
	}

	SERVICE_STATUS serviceStatus;
	ERRORCODE serviceStatusReturn = 0;
	if (!ControlService(service, SERVICE_CONTROL_INTERROGATE, &serviceStatus)) {
		serviceStatusReturn = CONTROL_SERVICE;
	}
	else if (serviceStatus.dwCurrentState == SERVICE_STOPPED)
	{
		serviceStatusReturn = PANO_SERVICE_STOPPED;
	}
	else if (serviceStatus.dwCurrentState == SERVICE_RUNNING)
	{
		serviceStatusReturn = PANO_SERVICE_RUNNING;
	}

	CloseServiceHandle(service);
	CloseServiceHandle(serviceControlManager);

	return serviceStatusReturn;
}

ERRORCODE StopWindowsDriver()
{
	SC_HANDLE serviceControlManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (serviceControlManager == NULL) {
		//cout << "Failed to open Service Control Manager. Error code: " << GetLastError() << endl;
		return NOT_SET;
	}

	// Open the service
	SC_HANDLE service = OpenServiceA(serviceControlManager, KERNEL_DRIVER_SERVICE_NAME, SERVICE_START | SERVICE_STOP);
	if (service == NULL) {
		//string message = format("Failed to open and stop the service. Error code: {}", GetLastError());
		//LogErrorMessage(message);

		CloseServiceHandle(serviceControlManager);
		return NOT_INSTALLED;
	}

	SERVICE_STATUS serviceStatus;
	if (!ControlService(service, SERVICE_CONTROL_STOP, &serviceStatus)) {
		DWORD errorCode = GetLastError();
		if (errorCode != ERROR_SERVICE_NOT_ACTIVE) {
			//string message = format("Error attempting to control the service: {}", GetLastError());
			//LogErrorMessage(message);
			return CONTROL_SERVICE;
		}
		else if (errorCode == ERROR_SERVICE_NOT_ACTIVE) {
			//LogInformationMessage("Service not running.");
			return PANO_SUCCESS;
		}
	}
	else {
		//LogInformationMessage("Service stopped successfully.");

		CloseServiceHandle(service);
		CloseServiceHandle(serviceControlManager);
		return PANO_SUCCESS;
	}
}

ERRORCODE StartWindowsDriver()
{
	SC_HANDLE serviceControlManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (serviceControlManager == NULL) {
		//string message = format("Failed to obtain a handle to the service control manager: {}", GetLastError());
		//LogErrorMessage(message);
		return NOT_SET;
	}

	SC_HANDLE service = OpenServiceA(serviceControlManager, KERNEL_DRIVER_SERVICE_NAME, SERVICE_START | SERVICE_STOP);
	if (service == NULL) {

		//string message = format("Failed to open and start the service. Error code: {}", GetLastError());
		//LogErrorMessage(message);

		CloseServiceHandle(serviceControlManager);
		return NOT_INSTALLED;
	}

	if (!StartService(service, 0, NULL)) {
		if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
			SERVICE_STATUS serviceStatus;
			//LogInformationMessage("Attempting to restart Panoptes Kernel Driver.");
			if (!ControlService(service, SERVICE_CONTROL_STOP, &serviceStatus)) {
				//string message = format("Error attempting to control the service: {}", GetLastError());
				//LogErrorMessage(message);
				return CONTROL_SERVICE;
			}

			//LogInformationMessage("Service stopped successfully.");
			if (!StartService(service, 0, NULL)) {
				//string message = format("Error restarting service: {}", GetLastError());
				//LogErrorMessage(message);
				return ERROR_STARTING_SERVICE;
			}
			//LogInformationMessage("Successfully restarted the Panoptes Kernel Driver");
		}
		else {
			//string message = format("Error starting service: {}", GetLastError());
			//LogErrorMessage(message);
			return ERROR_STARTING_SERVICE;
		}
	}

	CloseServiceHandle(service);
	CloseServiceHandle(serviceControlManager);

	return PANO_SUCCESS;
}


