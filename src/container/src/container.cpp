#include <grpcpp/grpcpp.h>
#include "panoptes.grpc.pb.h"
#include "panoptes.pb.h"
#include "container_ipc.hpp"
#include <ExtensibilityCore.h>
#include <iostream>
#include <atomic>

namespace fs = std::filesystem;

ExtensibilityCore::PanoBindPtr PanoBind;
ExtensibilityCore::PanoEntryPtr PanoEntry;
ExtensibilityCore::PanoUnbindPtr PanoUnbind;

PeMessageQueue* message_queue_pe_;
MemoryMessageQueue* message_queue_mem_;
std::atomic_bool isConnected = true;
std::unique_ptr<PanoptesService::Stub> stub;
int BindPort = 0;

/// @brief Get the gRPC port value from the registry.
/// @param portValue The port value that is read from the registry.
/// @return True if the port value is read successfully, false otherwise.
bool GetRegistryPortValue(DWORD& portValue)
{
	HKEY hKey;
	DWORD dwType = REG_DWORD;
	DWORD dwSize = sizeof(DWORD);

	// Open the key
	LONG lResult = RegOpenKeyExA(
		HKEY_LOCAL_MACHINE,
		"SOFTWARE\\Panoptes",
		0,
		KEY_READ,
		&hKey
	);

	if (lResult != ERROR_SUCCESS) {
		std::cerr << "Error opening registry key. Error code: " << lResult << std::endl;
		return false;
	}

	// Read the SRV_PORT value
	lResult = RegQueryValueExA(
		hKey,
		"SRV_PORT",
		NULL,
		&dwType,
		reinterpret_cast<LPBYTE>(&portValue),
		&dwSize
	);

	RegCloseKey(hKey);

	if (lResult != ERROR_SUCCESS) {
		std::cerr << "Error reading registry value. Error code: " << lResult << std::endl;
		return false;
	}

	if (dwType != REG_DWORD) {
		std::cerr << "Unexpected value type in registry." << std::endl;
		return false;
	}

	return true;
}

/// @brief The MessageQueueThread function is a thread that dequeues messages from the message 
/// queue and processes them in the PanoEntry function of the loaded extensibility DLL.
void MessageQueueThread() {
	message_queue_pe_ = new PeMessageQueue();
	while (isConnected) {
		PeScan pe_data = message_queue_pe_->dequeue();
		if (pe_data.PePath != "")
		{
			PanoEntry(&pe_data, NULL);
		}
	}
}

/// @brief The HealthCheck function is a thread that checks the health of the Panoptes main service.
void HealthCheck() {
	DWORD portValue = 0;
	if (!GetRegistryPortValue(portValue)) {
		std::cerr << "Failed to get registry port value." << std::endl;
		return;
	}
	std::string server_url = "localhost:" + std::to_string(portValue);

	while (true)
	{
		std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(server_url, 
		grpc::InsecureChannelCredentials());

		stub = PanoptesService::NewStub(channel);

		grpc::ClientContext context;
		HealthCheckRequest request;
		HealthCheckResponse response;
		request.set_ping(true);


		grpc::Status status = stub->HealthCheck(&context, request, &response);

		if (!status.ok()) {
			isConnected.store(false);
			return;
		}

		Sleep(2500);
	}
}

/// @brief The LoadExtensibility function is a function that loads the extensibility DLL.
/// @param dllFile The path to the extensibility DLL.
/// @return True if the extensibility DLL is loaded successfully, false otherwise.
bool LoadExtensibility(std::string dllFile) {
	HMODULE extensibility = LoadLibraryA(dllFile.c_str());
	if (extensibility == NULL) {
		DWORD error = GetLastError();
		return false;
	}
	else {
		PanoBind = (ExtensibilityCore::PanoBindPtr)GetProcAddress(extensibility, "PanoBind");
		if (PanoBind == NULL) {
			return false;
		}
		PanoEntry = (ExtensibilityCore::PanoEntryPtr)GetProcAddress(extensibility, "PanoEntry");
		if (PanoEntry == NULL) {
			return false;
		}
		PanoUnbind = (ExtensibilityCore::PanoUnbindPtr)GetProcAddress(extensibility, "PanoUnbind");
		if (PanoUnbind == NULL) {
			return false;
		}
	}

	return true;
}

/// @brief The BindToServiceWithRetry function is a function that binds to the Panoptes main service
/// with a retry mechanism.
/// @param containerPort The port value that is read from the registry.
/// @param maxAttempts The maximum number of attempts to bind to the service.
/// @param baseSleep The base sleep time in milliseconds.
/// @param multiplier The multiplier for the sleep time.
/// @return True if the service is bound successfully, false otherwise.
bool BindToServiceWithRetry(int containerPort, int maxAttempts, int baseSleep, double multiplier) {

	for (int attempt = 0; attempt < maxAttempts; ++attempt) {
		PanoBind(containerPort);
		if (BindPort > 0)
			break;

		if (attempt < maxAttempts - 1) {  // Don't sleep after the last attempt
			int sleep_duration_ms = baseSleep * std::pow(multiplier, attempt);
			std::cout << "Sleeping for " << sleep_duration_ms << " ms" << std::endl;
			std::this_thread::sleep_for(std::chrono::milliseconds(sleep_duration_ms));
		}
	}

	return true;
}

/// @brief The WinMain function is the entry point for the container.
/// @param hInstance The instance of the application.
/// @param hPrevInstance The previous instance of the application.
/// @param lpCmdLine The command line arguments.
/// @param nCmdShow The command line arguments.
/// @return The exit code of the application.
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	if (__argc < 1) {
		printf("No Args");
		exit(1);
	}

	std::string dllPath(__argv[1]);
	if (!LoadExtensibility(dllPath)) {
		printf("Error Loading Extensibility");
		exit(1);
	}

	HANDLE grpcServerThread = CreateThread(
		NULL,                   // default security attributes
		0,                      // default stack size
		(LPTHREAD_START_ROUTINE)RunContainerServer,   // thread function
		&BindPort,                   // no thread function arguments
		0,                      // default creation flags
		NULL                    // receive thread identifier
	);
	Sleep(2000);
	if (grpcServerThread == NULL || BindPort == 0)
	{
		std::cout << "Error creating thread: " << GetLastError() << std::endl;
		PanoUnbind();
		return 1;
	}

	if (!BindToServiceWithRetry(BindPort, 7, 1000, 2))
	{
		std::cout << "Error Binding to service: " << GetLastError() << std::endl;
		PanoUnbind();
		return 1;
	}

	HANDLE healthCheckThread = CreateThread(
		NULL,                   // default security attributes
		0,                      // default stack size
		(LPTHREAD_START_ROUTINE)HealthCheck,   // thread function
		NULL,                   // no thread function arguments
		0,                      // default creation flags
		NULL                    // receive thread identifier
	);
	Sleep(2000);
	if (healthCheckThread == NULL || BindPort == 0)
	{
		std::cout << "Error creating thread: " << GetLastError() << std::endl;

		PanoUnbind();
		return 1;
	}

	HANDLE messageQueueThread = CreateThread(
		NULL,                   // default security attributes
		0,                      // default stack size
		(LPTHREAD_START_ROUTINE)MessageQueueThread,   // thread function
		NULL,                   // no thread function arguments
		0,                      // default creation flags
		NULL                    // receive thread identifier
	);
	Sleep(2000);
	if (healthCheckThread == NULL || BindPort == 0)
	{
		std::cout << "Error creating thread: " << GetLastError() << std::endl;
		PanoUnbind();
		return 1;
	}

	while (true)
	{
		if (isConnected == false) {
			exit(1);
		}
		Sleep(2500);
	}

	return 0;
}
