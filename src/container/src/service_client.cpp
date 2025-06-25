#include "container_ipc.hpp"

#include <grpcpp/grpcpp.h>
#include "panoptes.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

std::unique_ptr<PanoptesService::Stub> stub_;

/// @brief The PanoptesServiceClient class is a class that implements the PanoptesServiceClient 
/// class.
/// @return The PanoptesServiceClient class.
PanoptesServiceClient::PanoptesServiceClient(){
	std::string server_url = "localhost:" + std::to_string(SERVICE_PORT);
	std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(server_url, grpc::InsecureChannelCredentials());
	stub_ = PanoptesService::NewStub(channel);
}

/// @brief The Hello function sends a Hello message to the Panoptes main service from the container.
/// @param extensibilityType The type of extensibility.
/// @param port The port of the Panoptes main service.
/// @return True if the Hello message is sent successfully, false otherwise.
bool PanoptesServiceClient::Hello(ExtensibilityType extensibilityType, std::string port) {
	AckMessage reply;
	ContainerInfo request;
	ClientContext g_context;

	int grpc_port = std::stoi(port);
	request.set_container_type((ContainerType)extensibilityType);
	request.set_grpc_port(grpc_port);

	Status status = stub_->Hello(&g_context, request, &reply);

	if (!status.ok()) {
		std::cout << status.error_code() << ": " << status.error_message() << std::endl;
		return !reply.ack_type();
	}
	
	return !reply.ack_type();
}

//bool PanoptesServiceClient::SendResults_Yara(std::string PePath, std::string FileHash, DWORD ProcessId, std::string YaraRulesPath, INT MatchRules, std::vector<std::string> DetectedRules) {
//	ClientContext context;
//	AckMessage reply;
//	ContainerReply request;
//
//	ScanYara results;
//	results.set_portable_executable_path(PePath);
//	results.set_file_hash(FileHash);
//	results.set_process_id(ProcessId);
//	results.set_rules_path(YaraRulesPath);
//	results.set_detected_rule_count(MatchRules);
//
//	for (int i = 0; i < DetectedRules.size(); i++) {
//		std::string detectionRuleName = DetectedRules[i];
//		results.add_detected_rules(detectionRuleName);
//	}
//
//	request.mutable_yara_scan()->CopyFrom(results);
//
//	Status status = stub_->ScanResults(&context, request, &reply);
//
//	if (!status.ok()) {
//		std::cout << status.error_code() << ": " << status.error_message() << std::endl;
//	}
//
//	return reply.ack_type();
//}
//
//bool PanoptesServiceClient::SendResults_PE(std::string PePath, bool IsPeSigned, std::string PeSignerSubject, std::vector<std::string> PeImports) {
//	AckMessage reply;
//	ContainerReply request;
//	ClientContext g_context;
//
//	ScanPE results;
//	results.set_portable_executable_path(PePath);
//	results.set_file_hash(PePath);
//	results.set_signed_(IsPeSigned);
//	results.set_signer(PeSignerSubject);
//	for (int i = 0; i < PeImports.size(); i++) {
//		results.add_imports(PeImports[i]);
//	}
//	request.mutable_pe_scan()->CopyFrom(results);
//
//	Status status = stub_->ScanResults(&g_context, request, &reply);
//
//	if (!status.ok()) {
//		std::cout << status.error_code() << ": " << status.error_message() << std::endl;
//	}
//
//	return reply.ack_type();
//}
//
//bool PanoptesServiceClient::SendResults_AMSI(std::string PePath, DWORD AmsiResult) {
//	AckMessage reply;
//	ContainerReply request;
//	ClientContext g_context;
//	
//	ScanAMSI results;
//	results.set_portable_executable_path(PePath);
//	results.set_amsi_result(AmsiResult);
//
//	request.mutable_amsi_scan()->CopyFrom(results);
//
//	Status status = stub_->ScanResults(&g_context, request, &reply);
//
//	if (!status.ok()) {
//		std::cout << status.error_code() << ": " << status.error_message() << std::endl;
//		return !reply.ack_type();
//	}
//
//	return !reply.ack_type();
//}
