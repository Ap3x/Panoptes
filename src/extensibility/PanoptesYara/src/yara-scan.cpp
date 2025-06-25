#include "PanoptesYara.h"
#include <iostream>
#include <fstream>
#include <stdexcept>

/// @brief Read a file to a buffer
/// @param filename The path to the file to read
/// @return A vector of uint8_t containing the file data
std::vector<uint8_t> readFileToBuffer(const std::string& filename) {
	std::ifstream file(filename, std::ios::binary | std::ios::ate);
	std::vector<uint8_t> buffer;

	if (!file.is_open()) {
		std::cerr << "Error: Could not open file " << filename << " for reading." << std::endl;
		return buffer; // Return empty buffer
	}

	// Get the file size
	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);

	// Reserve space in the buffer
	buffer.resize(size);

	// Read the file
	if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
		std::cerr << "Error: Failed to read data from file " << filename << std::endl;
		buffer.clear(); // Clear the buffer on error
	}

	file.close();
	return buffer;
}

/// @brief Intializes Yara memory and attempts to load supplied yara rules
/// @param rulesPath 
YaraScanner::YaraScanner(const char* rulesPath){
	YRX_RESULT result = YRX_NOT_SUPPORTED; 

	auto readBuffer = readFileToBuffer(rulesPath);
	
	if (readBuffer.empty()) {
		throw std::runtime_error("Failed to read rules file");
	}

	result = yrx_rules_deserialize(readBuffer.data(), readBuffer.size(), &g_yaraRules);
	if (result != YRX_SUCCESS) {
		throw std::runtime_error("Failed to deserialize YARA rules");
	}	
}

/// @brief Destructor for the YaraScanner class that destroys the YARA rules
YaraScanner::~YaraScanner() {
    if (g_yaraRules != nullptr) {
        yrx_rules_destroy(g_yaraRules);
        g_yaraRules = nullptr;
    }
}

/// @brief Callback function for the YARA rules
/// @param rule The rule that was matched
/// @param user_data The user data that was passed to the callback containing the detected rules
void matchingRule(const struct YRX_RULE* rule, void* user_data) {
	const uint8_t* ns;
	size_t ns_len;
	const uint8_t* ident;
	size_t ident_len;
	std::vector<string>* detectedRules = (std::vector<string>*)user_data;

	//yrx_rule_iter_metadata(rule, metaCallback, user_data);
	yrx_rule_namespace(rule, &ns, &ns_len);
	yrx_rule_identifier(rule, &ident, &ident_len);

	detectedRules->push_back(std::string(ns, ns + ns_len) + "::" + 
		std::string(ident, ident + ident_len));
}

/// @brief Scan a file using YARA rules
/// @param file_path The path to the file to scan
/// @return A vector of strings containing the detected rules
std::vector<string> YaraScanner::YaraScanFile(std::string file_path)
{
	std::vector<string> detectedRules;
	YRX_RESULT result = YRX_SUCCESS;
	YRX_SCANNER* scanner = nullptr;

	if (g_yaraRules == nullptr) {
		throw std::runtime_error("YARA rules not initialized");
	}

	try {
		result = yrx_scanner_create(g_yaraRules, &scanner);
		if (result != YRX_SUCCESS) {
			throw std::runtime_error("Failed to create YARA scanner");
		}

		result = yrx_scanner_on_matching_rule(scanner, matchingRule, &detectedRules);
		if (result != YRX_SUCCESS) {
			if (scanner != nullptr) {
				yrx_scanner_destroy(scanner);
			}
			throw std::runtime_error("Failed to set matching rule callback");
		}

		std::vector<uint8_t> scanBuffer = readFileToBuffer(file_path);
		if (scanBuffer.empty()) {
			if (scanner != nullptr) {
				yrx_scanner_destroy(scanner);
			}
			throw std::runtime_error("Failed to read file for scanning");
		}

		result = yrx_scanner_scan(scanner, scanBuffer.data(), scanBuffer.size());
		if (result != YRX_SUCCESS) {
			if (scanner != nullptr) {
				yrx_scanner_destroy(scanner);
			}
			throw std::runtime_error("Failed to scan file");
		}
	}
	catch (...) {
		if (scanner != nullptr) {
			yrx_scanner_destroy(scanner);
		}
		throw; // Re-throw the exception after cleanup
	}

	// Clean up resources
	if (scanner != nullptr) {
		yrx_scanner_destroy(scanner);
	}

	return detectedRules;
}