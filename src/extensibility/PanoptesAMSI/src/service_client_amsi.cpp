#include <grpcpp/grpcpp.h>
#include "panoptes.grpc.pb.h"
#include "PanoptesAMSI.h"

using grpc::ClientContext;
using grpc::Status;

std::unique_ptr<PanoptesService::Stub> stub_;

/// @brief Get the Panoptes Service port from the registry
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

/// @brief Constructor for the Panoptes Service Client to set up the connection to the 
/// Panoptes Service
PanoptesServiceClient::PanoptesServiceClient() {
	DWORD portValue;
	if (!GetRegistryPortValue(portValue)) {
		std::cerr << "Failed to get registry port value." << std::endl;
		return;
	}
	std::string server_url = "localhost:" + std::to_string(portValue);
	std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(server_url, grpc::InsecureChannelCredentials());
	stub_ = PanoptesService::NewStub(channel);
}

/// @brief Send a hello message to the Panoptes Service to bind to the service
/// @param extensibilityType The type of extensibility, in this case AMSI
/// @param ContainerPort The port of the container that the extensibility is running in
/// @return True if the hello message was sent successfully, false otherwise
bool PanoptesServiceClient::Hello(ExtensibilityType extensibilityType,int ContainerPort) {
	AckMessage reply;
	ContainerInfo request;
	ClientContext g_context;

	request.set_container_type((ContainerType)extensibilityType);
	request.set_grpc_port(ContainerPort);

	Status status = stub_->Hello(&g_context, request, &reply);

	if (!status.ok()) {
		std::cout << status.error_code() << ": " << status.error_message() << std::endl;
		exit(1);
	}

	return reply.ack_type();
}

/// @brief Send the results of the AMSI scan to the Panoptes Service
/// @param PePath The path of the file that was scanned
/// @param FileHash The hash of the file that was scanned
/// @param AmsiResult The result of the AMSI scan
/// @return True if the results were sent successfully, false otherwise
bool PanoptesServiceClient::SendResults_AMSI(
	std::string PePath,
	std::string FileHash, 
	DWORD AmsiResult) 
{
	AckMessage reply;
	ContainerReply request;
	ClientContext g_context;

	ScanAMSI results;
	request.set_portable_executable_path(PePath);
	request.set_file_hash(FileHash);
	results.set_amsi_result(AmsiResult);

	request.mutable_amsi_scan()->CopyFrom(results);

	Status status = stub_->ScanResults(&g_context, request, &reply);

	if (!status.ok()) {
		std::cout << status.error_code() << ": " << status.error_message() << std::endl;
		exit(1);
	}

	return !reply.ack_type();
}