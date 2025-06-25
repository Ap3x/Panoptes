#include <grpcpp/grpcpp.h>
#include "panoptes.pb.h"
#include "panoptes.grpc.pb.h"

#include "container_ipc.hpp"
#include <objbase.h>
#include <iostream>
#include <vector>

/// @brief The PeMessageQueue class is a thread-safe queue for PeScan messages.
/// @param message The PeScan message to enqueue.
/// @return True if the message is enqueued successfully, false otherwise.
PeMessageQueue::PeMessageQueue() {
	InitializeCriticalSection(&cs_);
	InitializeConditionVariable(&cv_);
}

/// @brief The enqueue function is a function that enqueues a PeScan message to the queue.
/// @param message The PeScan message to enqueue.
/// @return True if the message is enqueued successfully, false otherwise.
void PeMessageQueue::enqueue(const PeScan& message) {
	EnterCriticalSection(&cs_);
	queue_.push(message);
	std::cout << "Enqueued item. Queue size: " << queue_.size() << std::endl;
	LeaveCriticalSection(&cs_);
	WakeConditionVariable(&cv_);
}

/// @brief The dequeue function dequeues a PeScan messages from the queue.
/// @return The PeScan message that is dequeued.
PeScan PeMessageQueue::dequeue() {
	EnterCriticalSection(&cs_);
	while (queue_.empty()) {
		std::cout << "Queue empty, waiting..." << std::endl;
		SleepConditionVariableCS(&cv_, &cs_, INFINITE);
	}
	PeScan message = queue_.front();
	queue_.pop();
	// std::cout << "Dequeued item. Remaining queue size: " << queue_.size() << std::endl;
	LeaveCriticalSection(&cs_);
	return message;
}

/// @brief The enqueue function enqueues a MemScan message to the queue.
/// @param message The MemScan message to enqueue.
/// @return True if the message is enqueued successfully, false otherwise.
void MemoryMessageQueue::enqueue(const MemScan& message) {
	std::unique_lock<std::mutex> lock(mutex_);
	queue_.push(message);
	cv_.notify_one();
}

/// @brief The dequeue function dequeues a MemScan messages from the queue.
/// @return The MemScan message that is dequeued.
MemScan MemoryMessageQueue::dequeue() {
	std::unique_lock<std::mutex> lock(mutex_);
	cv_.wait(lock, [this] { return !queue_.empty(); });
	MemScan message = queue_.front();
	queue_.pop();

	return message;
}

/// @brief The PanoptesImpl class is a class that implements the PanoptesExtensibility::Service 
/// interface from the gRPC class.
class PanoptesImpl : public PanoptesExtensibility::Service {
	/// @brief The PEScan function queues a PeScan message to the queue.
	/// @param context The context of the server.
	/// @param request The request to scan the PE.
	/// @param response The response to the request.
	/// @return The status of the request.
	::grpc::Status PEScan(::grpc::ServerContext* context, const ::PeScanInfo* request, ::AckMessage* response) override {
		PeScan scanInfo;
		scanInfo.PePath = request->portable_executable_path();
		scanInfo.FileHash = request->file_hash();

		if (message_queue_pe_ != NULL) {
			message_queue_pe_->enqueue(scanInfo);
		}

		response->set_ack_type(AckType::SUCCESS);
		return ::grpc::Status::OK;
	}

	/// @brief The MemoryScan function queues a MemScan message to the queue.
	/// @param context The context of the server.
	/// @param request The request to scan the memory.
	/// @param response The response to the request.
	/// @return The status of the request.
	::grpc::Status MemoryScan(::grpc::ServerContext* context, const ::MemoryScanInfo* request, ::AckMessage* response) override {
		MemScan scanInfo;
		scanInfo.ProcessId = request->process_id();

		if (message_queue_pe_ != NULL) {
			message_queue_mem_->enqueue(scanInfo);
		}

		response->set_ack_type(AckType::SUCCESS);
		return ::grpc::Status::OK;
	}
};

/// @brief The RunContainerServer function is a function that runs the container server.
/// @param lpParam The port value that is read from the registry.
void RunContainerServer(LPVOID lpParam)
{
	int* ContainerPort = (int*)(lpParam);

	PanoptesImpl service;
	grpc::ServerBuilder builder;
	std::string server_url = "localhost:" + std::to_string(*ContainerPort);
	builder.AddListeningPort(server_url, grpc::InsecureServerCredentials(), ContainerPort);
	builder.RegisterService(&service);
	std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
	server->Wait();
}