#include <grpcpp/grpcpp.h>
#include "panoptes.grpc.pb.h"
#include "PanoptesML.h"
#include <iostream>

using grpc::ClientContext;
using grpc::Status;

static std::unique_ptr<PanoptesService::Stub> g_Stub;

// Debug builds of the service run unelevated and publish the port under HKCU
#ifdef _DEBUG
#define PANOPTES_REG_ROOT HKEY_CURRENT_USER
#else
#define PANOPTES_REG_ROOT HKEY_LOCAL_MACHINE
#endif

// How long a call to the service may take before it is given up
#define PANO_ML_RPC_TIMEOUT_MS 8000

/// @brief Reads the service's gRPC port from SOFTWARE\Panoptes\SRV_PORT
static bool GetServicePort(DWORD& Port)
{
	DWORD size = sizeof(Port);
	LONG result = RegGetValueA(PANOPTES_REG_ROOT, "SOFTWARE\\Panoptes", "SRV_PORT", RRF_RT_REG_DWORD, NULL, &Port, &size);
	if (result != ERROR_SUCCESS) {
		std::cerr << "PanoptesML: cannot read the service port (error " << result << ")" << std::endl;
		return false;
	}
	return true;
}

PanoptesServiceClient::PanoptesServiceClient()
{
	if (g_Stub != nullptr) {
		return; // one channel for the container's lifetime
	}
	DWORD port;
	if (!GetServicePort(port)) {
		return;
	}
	auto channel = grpc::CreateChannel("localhost:" + std::to_string(port), grpc::InsecureChannelCredentials());
	g_Stub = PanoptesService::NewStub(channel);
}

static void SetDeadline(ClientContext& Context)
{
	Context.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(PANO_ML_RPC_TIMEOUT_MS));
}

bool PanoptesServiceClient::Hello(ExtensibilityType Type, int ContainerPort)
{
	if (g_Stub == nullptr) {
		return false;
	}
	ClientContext context;
	SetDeadline(context);
	ContainerInfo request;
	request.set_container_type((ContainerType)Type);
	request.set_grpc_port(ContainerPort);

	AckMessage reply;
	Status status = g_Stub->Hello(&context, request, &reply);
	if (!status.ok()) {
		// The container retries PanoBind with backoff
		std::cerr << "PanoptesML: Hello failed: " << status.error_message() << std::endl;
		return false;
	}
	return reply.ack_type() == AckType::SUCCESS;
}

bool PanoptesServiceClient::SendResults_ML(const std::string& PePath, const std::string& FileHash, const MlScanResult& Result)
{
	if (g_Stub == nullptr) {
		return false;
	}
	ClientContext context;
	SetDeadline(context);
	ContainerReply request;
	request.set_portable_executable_path(PePath);
	request.set_file_hash(FileHash);

	ScanML* scan = request.mutable_ml_scan();
	scan->set_score(Result.Score);
	scan->set_threshold(PANO_ML_THRESHOLD);
	scan->set_malicious(Result.Malicious);
	scan->set_model(Result.Model);
	scan->set_feature_version(PANO_ML_FEATURE_VERSION);
	scan->set_is_pe(Result.IsPe);
	scan->set_error(Result.Error);

	AckMessage reply;
	Status status = g_Stub->ScanResults(&context, request, &reply);
	if (!status.ok()) {
		std::cerr << "PanoptesML: ScanResults failed: " << status.error_message() << std::endl;
		return false;
	}
	return reply.ack_type() == AckType::SUCCESS;
}
