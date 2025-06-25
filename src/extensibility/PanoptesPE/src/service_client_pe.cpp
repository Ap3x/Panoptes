#include <grpcpp/grpcpp.h>
#include "panoptes.grpc.pb.h"
#include "PanoptesPE.h"

using grpc::ClientContext;
using grpc::Status;

std::unique_ptr<PanoptesService::Stub> stub_;

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

bool PanoptesServiceClient::Hello(ExtensibilityType extensibilityType, int ContainerPort) {
	AckMessage reply;
	ContainerInfo request;
	ClientContext g_context;

	request.set_container_type((ContainerType)extensibilityType);
	request.set_grpc_port(ContainerPort);

	Status status = stub_->Hello(&g_context, request, &reply);

	if (!status.ok()) {
		//std::cout << status.error_code() << ": " << status.error_message() << std::endl;
		exit(1);
	}

	return reply.ack_type();
}

bool PanoptesServiceClient::SendResults_PE(std::string PePath, PortableExecutable::PEScanData data) {
	AckMessage reply;
	ContainerReply request;
	ClientContext g_context;

	ScanPE results;
	request.set_portable_executable_path(PePath);
	request.set_file_hash(PePath);
	results.set_signed_(data.isSigned);
	for (int i = 0; i < data.imports.size(); i++) {
		results.add_imports(data.imports[i]);
	}

	for (int i = 0; i < data.sections.size(); i++) {
		results.add_sections(data.sections[i]);
	}

	for (int i = 0; i < data.section_entropy.size(); i++) {
		results.add_section_entropy(data.section_entropy[i]);
	}

	request.mutable_pe_scan()->CopyFrom(results);

	Status status = stub_->ScanResults(&g_context, request, &reply);

	if (!status.ok()) {
		//std::cout << status.error_code() << ": " << status.error_message() << std::endl;
		exit(1);
	}

	return reply.ack_type();
}
