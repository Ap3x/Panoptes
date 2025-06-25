#include <Windows.h>
#include <iostream>
#include <string>
#include "scanner_ipc.hpp"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include <nlohmann/json.hpp>

ABSL_FLAG(std::string, file, "", "File for Panoptes To Scan");

int main() {
	absl::ParseCommandLine(__argc, __argv);
	if (absl::GetFlag(FLAGS_file).empty()) {
		printf("ERROR: No file specified\n");
		printf("Usage: PanoptesScanCLI.exe -file <FILE_TO_SCAN> \n");
		return 1;
	}

	std::string fileToScan = absl::GetFlag(FLAGS_file);
	PanoptesServiceClient client = PanoptesServiceClient();

	std::string results;
	if (!client.QueuePeScan(fileToScan, "", results)) {
		std::cout << "An Error Occured:" << "\n" << results << std::endl;
		return 1;
	}

	//Assuming the file hasnt been scanned before the return will be empty
	if (results.empty()) {
		Sleep(2000);
		//Scan the file again to get the results from the database
		if (!client.QueuePeScan(fileToScan, "", results)) {
			std::cout << "An Error Occured:" << "\n" << results << std::endl;
			return 1;
		}

		if (results.empty()) {
			std::cout << "Failed to get scan results\n" << std::endl;
			return 1;
		}
	}

	//If the file has been scanned before the return will be the results of the scan
	nlohmann::json j = nlohmann::json::parse(results);
	std::string prettyJson = j.dump(4, ' ', true);
	std::cout << "Scan Results:" << "\n" << prettyJson << std::endl;


	return 0;
}
