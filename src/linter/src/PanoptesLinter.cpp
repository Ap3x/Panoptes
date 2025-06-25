#include "PanoptesLinter.h"
#include "Configuration.hpp"

/// @brief The acceptable configuration parameters
std::vector<std::string> AcceptableConfigParams = {
	"ExtensibilitySelected", 
	"Exclusions",
	"IgnoreDriver",
	"QuarantineMaliciousFiles",
	"EventProviders"
};

/// @brief The required configuration parameters
std::vector<std::string> RequiredConfigParams = {
	"ExtensibilitySelected",
	"EventProviders"
};

/// @brief Check if a file exists
/// @param filePath The path to the file
/// @return True if the file exists, false otherwise
bool FileExists(const std::string& filePath) {
	DWORD fileAttributes = GetFileAttributesA(filePath.c_str());
	return (fileAttributes != INVALID_FILE_ATTRIBUTES &&
		!(fileAttributes & FILE_ATTRIBUTE_DIRECTORY));
}

/// @brief Remove a string from a vector
/// @param vec The vector to remove the string from
/// @param str The string to remove
void RemoveStringFromVector(std::vector<std::string>& vec, const std::string& str) {
	vec.erase(std::remove(vec.begin(), vec.end(), str), vec.end());
}

/// @brief Check if a string is in a vector
/// @param vec The vector to check
/// @param str The string to check
/// @return True if the string is in the vector, false otherwise
bool IsStringInVector(const std::vector<std::string>& vec, const std::string& str) {
	return std::find(vec.begin(), vec.end(), str) != vec.end();
}

int main(int argc, char* argv[]) {
		bool goodConfig = false;

	if (argc < 2) {
		std::cerr << "[!] Missing configuration file path" << std::endl;
		return 1;
	}

	if (!FileExists(argv[1])) {
		std::cerr << "[!] Configuration file does not exist: " << argv[1] << std::endl;
		return 1;
	}

#pragma region Checking if the configuration file is a valid JSON file
	Configuration config = Configuration(argv[1]);
	try {
		config.IsValidJson();
	}
	catch (const nlohmann::json::parse_error& e) {
		std::cerr << "JSON parse error: " << e.what() << std::endl;
	}
	catch (const std::runtime_error& e) {
		//Checking for the error in the configuration file
		std::cerr << "[!] Error: " << e.what() << std::endl;
	}
#pragma endregion

#pragma region Check for unknown keys
	std::vector<std::string> keys;
	try {
		keys = config.GetJsonKeys();
	}
	catch (const std::runtime_error& e) {
		std::cerr << "[!] Error: " << e.what() << std::endl;
	}

	for (const auto& key : keys) {
		if (!IsStringInVector(AcceptableConfigParams, key)) {
			std::cerr << "[!] Invalid Panoptes Configuration Key: " << key << std::endl;
			goodConfig = false;
			continue;
		}
	}

#pragma endregion

#pragma region Check for required keys
	// Check for required keys
	for (const auto& key : keys) {
		if (IsStringInVector(RequiredConfigParams, key)) {
			RemoveStringFromVector(RequiredConfigParams, key);
		}
	}

	//Printing out the missing required keys
	if (RequiredConfigParams.size() > 0) {
		std::cerr << "[!] Missing Required Panoptes Configuration Key(s): " << std::endl;
		for (const auto& key : RequiredConfigParams) {
			std::cerr << key << std::endl;
		}
		std::cerr << std::endl;
	}

	if (RequiredConfigParams.size() == 0) {
		goodConfig = true;
	}
#pragma endregion

	end:
	if (goodConfig) {
		std::cout << "[+] Panoptes Configuration is valid" << std::endl;
	}
	else {
		std::cerr << "[!] Panoptes Configuration is invalid" << std::endl;
	}

}