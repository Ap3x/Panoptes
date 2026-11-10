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
