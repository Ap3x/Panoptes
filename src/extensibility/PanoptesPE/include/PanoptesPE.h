#pragma once
#include "ExtensibilityCore.h"
#include <vector>

#define VERSION "1.0.0"
using namespace std;

class PortableExecutable {
public:
	/// @brief The data that is sent to the Panoptes Service
	struct PEScanData {
		std::vector<std::string> imports;
		std::vector <std::string> sections;
		std::vector<double> section_entropy;
		bool isSigned;
	};

	PortableExecutable(std::string PortableExecutablePath);
	std::vector<std::string> GetImports();
	std::vector<std::pair<std::string, double>> GetSections();
	bool CheckIfSigned();
};

class PanoptesServiceClient {
public:
	PanoptesServiceClient();
	bool Hello(ExtensibilityType extensibilityType, int ContainerPort);
	bool SendResults_PE(std::string PePath, PortableExecutable::PEScanData data);
};
