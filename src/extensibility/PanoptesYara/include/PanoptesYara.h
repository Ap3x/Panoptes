#pragma once
#include "ExtensibilityCore.h"
#include <vector>
#include "yara_x.h"

#define VERSION "1.0.0"
using namespace std;

/// @brief The Panoptes Service Client that used to communicate via gRPC
class PanoptesServiceClient {
public:
	PanoptesServiceClient();
	bool Hello(ExtensibilityType extensibilityType, int ContainerPort);
	bool SendResults_Yara(std::string PePath, std::string FileHash, std::vector<std::string> DetectedRules);
};

/// @brief The YaraScanner class that is used to scan a file using YARA rules
class YaraScanner {
private:
	/// @brief The parsed YARA rules
	YRX_RULES* g_yaraRules = nullptr;
public:
	/// @brief The data that is sent to the Panoptes Service
	struct ScanData
	{
		int detections;
		std::vector<std::string> detectedRules;
	};

	YaraScanner(const char* Rules);
	~YaraScanner();
	std::vector<std::string> YaraScanFile(std::string PathToFile);
};
