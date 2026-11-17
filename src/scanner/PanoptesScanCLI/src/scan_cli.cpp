#include <Windows.h>
#include <cstdio>
#include <chrono>
#include <iostream>
#include <string>
#include "scanner_ipc.hpp"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include <nlohmann/json.hpp>

ABSL_FLAG(std::string, file, "", "File for Panoptes To Scan");
ABSL_FLAG(int, timeout, 120, "Seconds to wait for every extension's result (YARA, ML)");

static std::string Join(const std::vector<std::string>& Items) {
	std::string out;
	for (const auto& item : Items) {
		out += (out.empty() ? "" : ", ") + item;
	}
	return out;
}

static int Run();

// gRPC keeps working on its own threads after the last channel is gone (even past
// grpc_shutdown_blocking). Returning from main runs the C runtime's exit handlers while they do,
// and a thread then uses a lock the runtime has already torn down: an access violation on exit
// after every successful scan. So once the output is flushed, the process ends with _exit,
// which skips those handlers; Windows stops the other threads first. The CRT is linked
// statically, so nothing else is unloaded either
int main() {
	int result = Run();
	std::cout.flush();
	fflush(stdout);
	fflush(stderr);
	_exit(result);
}

static int Run() {
	absl::ParseCommandLine(__argc, __argv);
	if (absl::GetFlag(FLAGS_file).empty()) {
		printf("ERROR: No file specified\n");
		printf("Usage: PanoptesScanCLI.exe -file <FILE_TO_SCAN> [-timeout <SECONDS>]\n");
		return 1;
	}

	std::string fileToScan = absl::GetFlag(FLAGS_file);
	PanoptesServiceClient client = PanoptesServiceClient();

	// The service sends the file to every running extension (PanoptesYara, and PanoptesML when
	// installed) that hasn't scanned it yet. Each reports on its own, so wait until none is
	// pending. The waiting requests are polls: they start no scan and show no notification
	ScanReply reply;
	std::string error;
	if (!client.QueuePeScan(fileToScan, "", false, reply, error)) {
		std::cout << "An Error Occured:" << "\n" << error << std::endl;
		return 1;
	}
	if (!reply.Pending.empty()) {
		std::cout << "Waiting for: " << Join(reply.Pending) << std::endl;
	}
	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(absl::GetFlag(FLAGS_timeout));
	while (!reply.Pending.empty() && std::chrono::steady_clock::now() < deadline) {
		Sleep(500);
		std::string fileHash = reply.FileHash;
		if (!client.QueuePeScan(fileToScan, fileHash, true, reply, error)) {
			std::cout << "An Error Occured:" << "\n" << error << std::endl;
			return 1;
		}
	}

	if (reply.Results.empty()) {
		std::cout << "No scan results" << (reply.Pending.empty() ? "" : " after " + std::to_string(absl::GetFlag(FLAGS_timeout)) + " seconds") << std::endl;
		return 1;
	}
	nlohmann::json j = nlohmann::json::parse(reply.Results);
	std::string prettyJson = j.dump(4, ' ', true);
	std::cout << "Scan Results:" << "\n" << prettyJson << std::endl;
	if (!reply.Pending.empty()) {
		std::cout << "No result yet from: " << Join(reply.Pending) << std::endl;
		return 1;
	}
	return 0;
}
