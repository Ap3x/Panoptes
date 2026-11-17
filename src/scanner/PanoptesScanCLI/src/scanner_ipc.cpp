#include <grpcpp/grpcpp.h>
#include "panoptes.grpc.pb.h"
#include "scanner_ipc.hpp"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

class PanoptesService_Stub_Holder {
public:
	std::unique_ptr<PanoptesService::Stub> Stub;
};

// Debug builds of the service run unelevated and publish the port under HKCU
#ifdef _DEBUG
#define PANOPTES_REG_ROOT HKEY_CURRENT_USER
#else
#define PANOPTES_REG_ROOT HKEY_LOCAL_MACHINE
#endif // _DEBUG

/// @brief Get the Panoptes Service port value from the registry
/// @param portValue The port value from the registry
/// @return True if the port value was retrieved successfully, false otherwise
bool GetRegistryPortValue(DWORD& portValue) {
	HKEY hKey;
	DWORD dwType = REG_DWORD;
	DWORD dwSize = sizeof(DWORD);

	// Open the key
	LONG lResult = RegOpenKeyExA(
		PANOPTES_REG_ROOT,
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
	DWORD SERVICE_PORT = 0;
	GetRegistryPortValue(SERVICE_PORT);
	std::string server_url = "localhost:0" + std::to_string(SERVICE_PORT);
	std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(server_url, grpc::InsecureChannelCredentials());
	m_stub = std::make_unique<PanoptesService_Stub_Holder>();
	m_stub->Stub = PanoptesService::NewStub(channel);
}

bool PanoptesServiceClient::QueuePeScan(const std::string& PePath, const std::string& FileHash, bool Poll, ScanReply& Reply, std::string& Error) {
	AckMessage reply;
	ClientContext context;
	// The service only queues the scans; it answers quickly
	context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(30));

	PeScanInfo request;
	request.set_file_hash(FileHash);
	request.set_portable_executable_path(PePath);
	request.set_poll(Poll);

	Status status = m_stub->Stub->QueuePeScan(&context, request, &reply);
	if (!status.ok()) {
		Error = status.error_message();
		return false;
	}
	Reply.Results = reply.message();
	Reply.FileHash = reply.file_hash();
	Reply.Pending.assign(reply.pending_scans().begin(), reply.pending_scans().end());
	return true;
}

PanoptesServiceClient::~PanoptesServiceClient() = default;
