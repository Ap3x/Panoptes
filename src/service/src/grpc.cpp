#include <grpcpp/grpcpp.h>
#include "panoptes.grpc.pb.h"

#include "panoptes_service.h"
#include "grpc.hpp"
#include "hash.h"
#include "pano_log.h"
#include "utils.h"
#include "service_constants.h"

#include "tray_notifications.h"
#include "Configuration.hpp"
#include "detector.h"
#include "detector_stream.h"
#include "process_images.h"
#include <atomic>
#include <vector>
#include <string>
#include <algorithm>
#include <filesystem>
#include <regex>
#include <mutex>
#include <chrono>
#include <filesystem>

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

std::unique_ptr<PanoptesExtensibility::Stub> stub_;
std::unique_ptr<PanoptesService::Stub> selfStub_;
std::vector<std::pair<ContainerType, int>> g_containerServerPorts;
PanoptesContext* serviceContext;
// The port the server listens on, set once it has started. The detector RPCs use it to find
// the calling process
static std::atomic<int> g_serverPort{ 0 };

// How long a SubscribeEvents call waits for events before checking whether it was cancelled
#define PANO_DETECTOR_POLL_MS 250

// A Windows header defines PERMISSION_DENIED as a macro, which breaks StatusCode::PERMISSION_DENIED
#pragma push_macro("PERMISSION_DENIED")
#undef PERMISSION_DENIED
static ::grpc::Status PermissionDenied(const std::string& why) {
	return ::grpc::Status(::grpc::StatusCode::PERMISSION_DENIED, why);
}
#pragma pop_macro("PERMISSION_DENIED")

// "DETECTION_SEVERITY_MEDIUM" without its prefix, lowercased: "medium"
static std::string EnumWord(const std::string& name, const std::string& prefix) {
	std::string word = name.rfind(prefix, 0) == 0 ? name.substr(prefix.size()) : name;
	std::transform(word.begin(), word.end(), word.begin(), [](unsigned char c) { return (char)std::tolower(c); });
	return word;
}


namespace fs = std::filesystem;

bool MoveFileToQuarantine(std::string filePath) {
	std::string quarantinePath = "C:\\ProgramData\\Panoptes\\Quarantine";

    std::error_code error;
    fs::create_directories(quarantinePath, error);
    std::filesystem::path sourcePath(filePath);
    std::filesystem::path destinationPath = fs::path(quarantinePath) / sourcePath.filename();
    try {
        fs::rename(sourcePath, destinationPath);
    }
    catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error moving file to quarantine: " << e.what() << std::endl;
        return false;
    }
    return true;
}

bool GetRegistryPortValue(DWORD& portValue)
{
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

bool CheckIfMalicious(std::string jsonString) {
	nlohmann::json jsonObject = nlohmann::json::parse(jsonString);
	if (jsonObject.contains("yara_scan") && jsonObject["yara_scan"].contains("detected_rules"))
	{
		nlohmann::json yaraObject = jsonObject["yara_scan"];
		int detected_rules = yaraObject["detected_rules"].size();
		if (detected_rules > 0) {
			return true;
		}
	}

	return false;
}

bool CreateRegistryEntryWithPort(DWORD dwPort) {
	HKEY hKey;
	DWORD dwDisposition;

	// Create or open the key
	LONG lResult = RegCreateKeyExA(
		PANOPTES_REG_ROOT,
		"SOFTWARE\\Panoptes",
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS,
		NULL,
		&hKey,
		&dwDisposition
	);

	if (lResult != ERROR_SUCCESS) {
		std::cerr << "Error creating/opening registry key. Error code: " << lResult << std::endl;
		return false;
	}

	// Set the SRV_PORT value
	lResult = RegSetValueExA(
		hKey,
		"SRV_PORT",
		0,
		REG_DWORD,
		reinterpret_cast<const BYTE*>(&dwPort),
		sizeof(dwPort)
	);

	if (lResult != ERROR_SUCCESS) {
		std::cerr << "Error setting registry value. Error code: " << lResult << std::endl;
		RegCloseKey(hKey);
		return false;
	}

	RegCloseKey(hKey);
	std::cout << "Registry entry created successfully." << std::endl;
	return true;
}

std::string CleanUpProtobufMessage(std::string msg) {
	size_t pos;
	while ((pos = msg.find("\\u0000")) != std::string::npos) {
		msg.erase(pos, 6);
	}

	nlohmann::json j = nlohmann::json::parse(msg);
	std::time_t now = std::time(nullptr);
	std::string formattedTime = FormatTime(now);
	j["Time"] = std::string(formattedTime);
	std::string dumpAgain = j.dump();

	return dumpAgain;
}

PanoptesContainerClient::PanoptesContainerClient(int containerPort) {
	std::string server_url = "localhost:" + std::to_string(containerPort);
	std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(server_url, grpc::InsecureChannelCredentials());
	stub_ = PanoptesExtensibility::NewStub(channel);
}

bool PanoptesContainerClient::SendPeScanRequest(std::string pePath, std::string fileHash) {
	AckMessage reply;
	ClientContext context;

	PeScanInfo request;
	request.set_file_hash(fileHash);
	request.set_portable_executable_path(pePath);

	Status status = stub_->PEScan(&context, request, &reply);
	if (!status.ok()) {
		std::cout << status.error_code() << ": " << status.error_message() << std::endl;
	}

	return reply.ack_type();
}

void SelfQueuePeScan(std::string pePath, std::string fileHash) {
	auto configuration = serviceContext->config;
	if (Configuration::IsPathInList(configuration->m_exclusions, pePath)) {
		return;
	}

	DWORD containerPort = 0;
	GetRegistryPortValue(containerPort);
	std::string server_url = "localhost:" + std::to_string(containerPort);
	std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(server_url, grpc::InsecureChannelCredentials());
	selfStub_ = PanoptesService::NewStub(channel);

	AckMessage reply;
	ClientContext context;
	PeScanInfo request;
	request.set_file_hash(fileHash);
	request.set_portable_executable_path(pePath);

	Status status = selfStub_->QueuePeScan(&context, request, &reply);
	if (!status.ok()) {
		std::cout << status.error_code() << ": " << status.error_message() << std::endl;
	}
}

class PanoptesImpl : public PanoptesService::Service {
	::grpc::Status ScanResults(::grpc::ServerContext* context, const ::ContainerReply* request, ::AckMessage* response) override {
		google::protobuf::util::JsonPrintOptions options;
		auto configuration = serviceContext->config;
		options.add_whitespace = false;
		// options.always_print_primitive_fields = true;
		options.preserve_proto_field_names = true;
		options.always_print_enums_as_ints = false;


		std::string fileHash = request->file_hash();
		std::string filePath = request->portable_executable_path();
		std::string json_string;
		// The log line, the database entry and the detection check below are all built from
		// this JSON, so a scan result that cannot be converted is rejected rather than stored
		// as an empty or partial entry
		auto jsonStatus = google::protobuf::util::MessageToJsonString(*request, &json_string, options);
		if (!jsonStatus.ok()) {
			std::string message = "Failed to convert the scan result for " + filePath + " to JSON: " + jsonStatus.ToString();
			std::cerr << message << std::endl;
			return ::grpc::Status(::grpc::StatusCode::INTERNAL, message);
		}
		std::string cleanMsg = CleanUpProtobufMessage(json_string);
		WriteToLogFile(cleanMsg + "\n");

		serviceContext->database = PanoptesDatabase();
		auto loadedDB = serviceContext->database.load();
		std::string entry = loadedDB.GetEntry(fileHash);
		if (entry.empty()) {
			loadedDB.AddEntry(fileHash, cleanMsg);
			entry = cleanMsg;
		}
		else
		{
			entry = loadedDB.UpdateEntry(fileHash, cleanMsg);
		}

		if (CheckIfMalicious(entry)) {
			std::string displayMessage = "Malicious File Detected: " + GetBaseName(filePath);
			TrayNotifications::Tray::ShowTrayIconBalloon("Panoptes EDR Detection", displayMessage.c_str());

			if (configuration->m_quartine) {
				MoveFileToQuarantine(filePath);
			}
		}

		response->set_ack_type(SUCCESS);
		return ::grpc::Status::OK;
	}

	::grpc::Status QueuePeScan(::grpc::ServerContext* context, const ::PeScanInfo* request, ::AckMessage* response) override {
		std::string fileToScan = request->portable_executable_path();
		if (fileToScan.empty()) {
			return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "PE path not provided");
		}

		auto configuration = serviceContext->config;
		if (Configuration::IsPathInList(configuration->m_exclusions, fileToScan)) {
			std::string message = "File is excluded from scan: " + fileToScan;
			return ::grpc::Status(::grpc::StatusCode::UNKNOWN, message);
		}

		std::string fileHash = request->file_hash();
		if (fileHash.empty()) {
			fileHash = GenerateMD5(fileToScan);
			if (fileHash.empty()) {
				std::string message = "Failed to generate hash for " + fileToScan;
				return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, message);
			}
		}

		auto loadedDB = serviceContext->database.load();
		std::string entry = loadedDB.GetEntry(fileHash);
		if (!entry.empty())
		{
			WriteToLogFile(entry + "\n");
			response->set_ack_type(AckType::SUCCESS);
			response->set_message(entry);
			if (CheckIfMalicious(entry)) {
				std::string displayMessage = "Malicious File Detected: " + GetBaseName(fileToScan.c_str());
				TrayNotifications::Tray::ShowTrayIconBalloon("Panoptes EDR Detection", displayMessage.c_str());

				if (configuration->m_quartine) {
					MoveFileToQuarantine(request->portable_executable_path());
				}
			}
		}
		else {
			for (auto container : g_containerServerPorts) {
				PanoptesContainerClient client = PanoptesContainerClient(container.second);
				client.SendPeScanRequest(request->portable_executable_path(), fileHash);
			}
		}

		return ::grpc::Status::OK;
	}

	::grpc::Status HealthCheck(::grpc::ServerContext* context, const ::HealthCheckRequest* request, ::HealthCheckResponse* response) override {
		response->set_pong("pong");
		return ::grpc::Status::OK;
	}

	::grpc::Status Hello(::grpc::ServerContext* context, const ::ContainerInfo* request, ::AckMessage* response) override {
		if (request->container_type() == NULL) {
			return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "No container type provided");
		}

		std::cout << "Hello: " << request->container_type() << std::endl;

		std::pair<ContainerType, int> ContainerPortInfo = std::make_pair(request->container_type(), request->grpc_port());
		g_containerServerPorts.push_back(ContainerPortInfo);

		response->set_ack_type(AckType::SUCCESS);
		return ::grpc::Status::OK;
	}

	// Streams every logged event to the detector until it disconnects or the service stops
	::grpc::Status SubscribeEvents(::grpc::ServerContext* context, const ::DetectorHello* request, ::grpc::ServerWriter<::DetectorEvent>* writer) override {
		std::string why;
		if (!IsDetectorPeer(context->peer(), g_serverPort.load(), why)) {
			std::cerr << "SubscribeEvents refused: " << why << std::endl;
			return PermissionDenied(why);
		}

		std::vector<std::string> eventNames(request->event_names().begin(), request->event_names().end());
		auto subscription = DetectorSubscription::Open(eventNames);
		if (subscription == nullptr) {
			return ::grpc::Status(::grpc::StatusCode::RESOURCE_EXHAUSTED, "too many detectors subscribed, or the service is stopping");
		}
		std::cout << "Detector " << request->version() << " subscribed to events" << std::endl;

		std::vector<DetectorEventRecord> batch;
		::DetectorEvent message;
		while (!context->IsCancelled() && subscription->Wait(batch, PANO_DETECTOR_POLL_MS)) {
			for (auto& record : batch) {
				message.set_sequence(record.Sequence);
				message.set_timestamp(record.Timestamp);
				message.set_json(std::move(record.Json));
				// Blocks while the detector is behind; the publisher keeps queueing (or
				// dropping) meanwhile, so the event threads are never held up
				if (!writer->Write(message)) {
					std::cout << "Detector disconnected" << std::endl;
					return ::grpc::Status::OK;
				}
			}
		}
		return ::grpc::Status::OK;
	}

	// Logs a detection to pano.log, notifies, and carries out its action
	::grpc::Status ReportDetection(::grpc::ServerContext* context, const ::Detection* request, ::AckMessage* response) override {
		std::string why;
		if (!IsDetectorPeer(context->peer(), g_serverPort.load(), why)) {
			std::cerr << "ReportDetection refused: " << why << std::endl;
			return PermissionDenied(why);
		}

		std::string outcome = RespondToDetection(*request, *serviceContext->config);

		// Not published to the detector: it already knows, and no rule matches on it
		nlohmann::ordered_json event;
		event["Event"] = "Detection";
		event["Rule"] = request->rule();
		event["Description"] = request->description();
		// The same words the rules and detection.log use: "medium", "kill"
		event["Severity"] = EnumWord(DetectionSeverity_Name(request->severity()), "DETECTION_SEVERITY_");
		event["Action"] = EnumWord(DetectionAction_Name(request->action()), "DETECTION_ACTION_");
		event["PID"] = request->process_id();
		// The detector takes the image from the event, which is empty for processes that started
		// before the service; the service may still know it
		std::string image = request->image_path();
		if (image.empty()) {
			FILETIME matched;
			matched.dwLowDateTime = (DWORD)(request->timestamp() & 0xFFFFFFFF);
			matched.dwHighDateTime = (DWORD)((UINT64)request->timestamp() >> 32);
			image = ResolveProcessImage(request->process_id(), request->timestamp() != 0 ? matched : CurrentFileTime());
		}
		event["Image"] = image;
		// UTC in the format of every other line, so the log sorts and replays consistently
		event["Time"] = FormatSystemTime(CurrentFileTime());
		event["Response"] = outcome;
		event["EventSequences"] = std::vector<uint64_t>(request->event_sequences().begin(), request->event_sequences().end());
		WriteToLogFile(event.dump() + "\n");

		std::string displayMessage = request->rule() + " (PID " + std::to_string(request->process_id()) + (image.empty() ? "" : ", " + GetBaseName(image)) + "): " + outcome;
		TrayNotifications::Tray::ShowTrayIconBalloon("Panoptes EDR Detection", displayMessage.c_str());

		response->set_ack_type(AckType::SUCCESS);
		response->set_message(outcome);
		return ::grpc::Status::OK;
	}
};

// The running server, so StopServiceServer can shut it down from another thread.
// g_serverStopping covers a stop that arrives before the server has been built
static std::mutex g_serverLock;
static grpc::Server* g_server = nullptr;
static bool g_serverStopping = false;

// How long calls in flight get to finish before StopServiceServer cancels them
#define PANO_SERVER_SHUTDOWN_GRACE_MS 2000

VOID StopServiceServer()
{
	// Event streams only end when the detector disconnects, so they are ended first; otherwise
	// each would hold up shutdown until the grace period runs out
	StopDetectorStreams();

	std::lock_guard<std::mutex> lock(g_serverLock);
	g_serverStopping = true;
	if (g_server != nullptr) {
		g_server->Shutdown(std::chrono::system_clock::now() + std::chrono::milliseconds(PANO_SERVER_SHUTDOWN_GRACE_MS));
	}
}

void RunServiceServer(LPVOID lpParam)
{
	serviceContext = reinterpret_cast<PanoptesContext*>(lpParam);
	PanoptesImpl service;
	grpc::ServerBuilder builder;
	int selected_port = 0;
	std::string server_url = "localhost:0";

	//Setting the server address to localhost:0 will allow the OS to assign an available port
	builder.AddListeningPort(server_url, grpc::InsecureServerCredentials(), &selected_port);
	builder.RegisterService(&service);

	std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
	if (server == nullptr) {
		auto threadError = &serviceContext->threadError;
		bool threadState = threadError->load();
		threadError->store(true);
		return;
	}

	g_serverPort = selected_port;
	bool updatedReg = CreateRegistryEntryWithPort(selected_port);
	if (!updatedReg) {
		auto threadError = &serviceContext->threadError;
		bool threadState = threadError->load();
		threadError->store(true);
	}

	{
		std::lock_guard<std::mutex> lock(g_serverLock);
		if (g_serverStopping) {
			server->Shutdown();
		}
		g_server = server.get();
	}

	// Returns once StopServiceServer has shut the server down
	server->Wait();

	std::lock_guard<std::mutex> lock(g_serverLock);
	g_server = nullptr;
}