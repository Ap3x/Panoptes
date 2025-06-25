#include <grpcpp/grpcpp.h>
#include "panoptes.grpc.pb.h"

#include "panoptes_service.h"
#include "grpc.hpp"
#include "hash.h"
#include "pano_log.h"
#include "utils.h"

#include "TrayNotifications.h"
#include "Configuration.hpp"
#include <vector>
#include <string>
#include <algorithm>
#include <filesystem>
#include <regex>
#include <filesystem>
#include "PanoptesAMSI.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

std::unique_ptr<PanoptesExtensibility::Stub> stub_;
std::unique_ptr<PanoptesService::Stub> selfStub_;
std::vector<std::pair<ContainerType, int>> g_containerServerPorts;
PanoptesContext* serviceContext;


namespace fs = std::filesystem;

void MoveFileToQuarantine(std::string filePath) {
	std::string quarantinePath = "C:\\ProgramData\\Panoptes\\Quarantine";

    if (!fs::exists(quarantinePath)) {
        fs::create_directories(quarantinePath);
    }
    std::filesystem::path sourcePath(filePath);
    std::filesystem::path destinationPath = fs::path(quarantinePath) / sourcePath.filename();
    try {
        fs::rename(sourcePath, destinationPath);
    }
    catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error moving file to quarantine: " << e.what() << std::endl;
    }
}

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

bool isPathInExclusions(const std::vector<std::string>& exclusions, const std::string& fullPath)
{
	std::filesystem::path fullPathNormalized = std::filesystem::path(fullPath).lexically_normal();

	return std::any_of(exclusions.begin(), exclusions.end(),
		[&fullPathNormalized](const std::string& path) {
			std::filesystem::path pathNormalized = std::filesystem::path(path).lexically_normal();
			return fullPathNormalized.string().find(pathNormalized.string()) == 0;
		});
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

	if (jsonObject.contains("amsi_result"))
	{
		AmsiScanner::AMSI_RESULT_PANO amsiResult = jsonObject["amsi_result"];
		if (amsiResult == AmsiScanner::AMSI_RESULT_PANO_DETECTED) {
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
		HKEY_LOCAL_MACHINE,
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

bool PanoptesContainerClient::SendMemoryScanRequest(DWORD processId) {
	AckMessage reply;
	ClientContext g_context;

	MemoryScanInfo request;
	request.set_process_id(processId);

	Status status = stub_->MemoryScan(&g_context, request, &reply);

	if (!status.ok()) {
		std::cout << status.error_code() << ": " << status.error_message()
			<< std::endl;
	}

	return reply.ack_type();
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
	if (isPathInExclusions(configuration->m_exclusions, pePath)) {
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
		google::protobuf::util::MessageToJsonString(*request, &json_string, options);
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

		// The PE Module just provides extra analysis on top of the AMSI/Yara Scan
		if (!request->has_pe_scan()) {
			if (CheckIfMalicious(entry)) {
				std::string displayMessage = "Malicious File Detected: " + GetBaseName(filePath);
				TrayNotifications::Tray::ShowTrayIconBalloon("Panoptes EDR Detection", displayMessage.c_str());

				if (configuration->m_quartine) {
					MoveFileToQuarantine(filePath);
				}
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
		if (isPathInExclusions(configuration->m_exclusions, fileToScan)) {
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
				
				for (auto container : g_containerServerPorts) {
					if (container.first == ContainerType::CONTAINER_TYPE_PE) {
						PanoptesContainerClient client = PanoptesContainerClient(container.second);
						client.SendPeScanRequest(request->portable_executable_path(), fileHash);
					}
				}
			}
		}
		else {

			for (auto container : g_containerServerPorts) {
				if (container.first == ContainerType::CONTAINER_TYPE_PE) {
					continue;
				}
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
};

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
	}

	bool updatedReg = CreateRegistryEntryWithPort(selected_port);
	if (!updatedReg) {
		auto threadError = &serviceContext->threadError;
		bool threadState = threadError->load();
		threadError->store(true);
	}

	server->Wait();
}