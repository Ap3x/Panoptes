#include <grpcpp/grpcpp.h>
#include "panoptes.grpc.pb.h"
#include "scanner_ipc.hpp"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

std::unique_ptr<PanoptesService::Stub> stub_;

/// @brief Get the Panoptes Service port value from the registry
/// @param portValue The port value from the registry
/// @return True if the port value was retrieved successfully, false otherwise
bool GetRegistryPortValue(DWORD& portValue) {
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

/// @brief Constructor for the Panoptes Service Client
PanoptesServiceClient::PanoptesServiceClient() {
	DWORD SERVICE_PORT;
	GetRegistryPortValue(SERVICE_PORT);
	std::string server_url = "localhost:0" + std::to_string(SERVICE_PORT);
	std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(server_url, grpc::InsecureChannelCredentials());
	stub_ = PanoptesService::NewStub(channel);
}

/// @brief Send a request to the Panoptes Service to scan a PE file
/// @param PePath The path to the PE file
/// @param FileHash The hash of the PE file
/// @param message The message to send to the Panoptes Service
/// @return True if the request was sent successfully, false otherwise
bool PanoptesServiceClient::QueuePeScan(std::string PePath, std::string FileHash, std::string& message) {
	AckMessage reply;
	ClientContext context;
	std::chrono::system_clock::time_point deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(8000); // 8 second timeout
	context.set_deadline(deadline);
	PeScanInfo request;
	request.set_file_hash(FileHash);
	request.set_portable_executable_path(PePath);

	Status status = stub_->QueuePeScan(&context, request, &reply);
	if (!status.ok()) {
		if (status.error_code() != grpc::StatusCode::UNKNOWN || status.error_code() != grpc::StatusCode::DEADLINE_EXCEEDED) {
			message = status.error_message();
			return false;
		}
	}

	return true;
}
