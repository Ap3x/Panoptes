#include <Windows.h>
#include "Configuration.hpp"
#include "ResourceCore.h"
// #include "panoptes.pb.h"
#include <vector>
#include <sstream>

#pragma region Utility Functions
/// @brief Convert a string to a DWORD
/// @param str The string to convert
/// @return The DWORD value of the string
DWORD StringToDWORD(const std::string& str) {
	try {
		unsigned long value = std::stoul(str, nullptr, 0);
		return static_cast<DWORD>(value);
	}
	catch (const std::invalid_argument& e) {
		// Handle invalid input
		return 0; // or throw an exception, depending on your error handling strategy
	}
	catch (const std::out_of_range& e) {
		// Handle out of range input
		return 0; // or throw an exception, depending on your error handling strategy
	}
}

/// @brief Split a string into a vector of strings
/// @param input The string to split
/// @param delimiter The delimiter to split the string on
/// @return A vector of strings
std::vector<std::string> SplitString(const std::string& input, char delimiter = ',') {
	std::vector<std::string> result;
	std::stringstream ss(input);
	std::string item;

	while (std::getline(ss, item, delimiter)) {
		result.push_back(item);
	}

	return result;
}

/// @brief Convert a string to lowercase
/// @param str The string to convert
/// @return The lowercase string
std::string StrToLower(std::string str) {
	std::transform(str.begin(), str.end(), str.begin(),
		[](unsigned char c) { return std::tolower(c); });
	return str;
}
#pragma endregion

/// @brief Constructor for the Configuration class
/// @param configurationPath The path to the configuration file
Configuration::Configuration(std::string configurationPath)
{
	m_fileStream = std::ifstream(configurationPath);
}

/// @brief Parse the configuration file
void Configuration::Parse()
{
	m_data = nlohmann::json::parse(m_fileStream);
	GetExtensibilitySelected();
	GetScannerExclusions();
	GetIgnoreDriver();
	GetQuarantineMaliciousFiles();
	GetEventProviders();
}

/// @brief Check if the configuration file is valid
void Configuration::IsValidJson()
{
	m_data = nlohmann::json::parse(m_fileStream);
}

/// @brief Get the event providers from the configuration file
void Configuration::GetEventProviders() {
	if (m_data["EventProviders"].is_array()) {

		std::vector<std::string> selectedExtensibility = m_data["EventProviders"].template get<std::vector<std::string>>();

		for (std::string containerTypeStr : selectedExtensibility) {
			auto splitStr = SplitString(containerTypeStr, ',');
			if (splitStr.size() != 3) {
				throw std::runtime_error("Invalid Event Provider format");
			}

			std::string providerName = splitStr[0];
			unsigned long providerMatchAnyKeyword = StringToDWORD(splitStr[1]);
			unsigned long providerMatchAllKeyword = StringToDWORD(splitStr[2]);

			auto eventProviderInfo = std::make_tuple(providerName, providerMatchAnyKeyword, providerMatchAllKeyword);
			m_eventProviders.push_back(eventProviderInfo);
		}
	}
	else {
		throw std::runtime_error("EventProviders was not set in the the configuration");
	}
}

/// @brief Get the extensibility selected from the configuration file
void Configuration::GetExtensibilitySelected()
{
	if (m_data["ExtensibilitySelected"].is_array()) {
		std::vector<std::string> selectedExtensibility = m_data["ExtensibilitySelected"].template get<std::vector<std::string>>();

		for (std::string containerTypeStr : selectedExtensibility) {
			ContainerType containerType;


			if (StrToLower(containerTypeStr) == "amsi") {
				containerType = CONTAINER_TYPE_AMSI;
			}
			else if (StrToLower(containerTypeStr) == "pe") {
				containerType = CONTAINER_TYPE_PE;
			}
			else if (StrToLower(containerTypeStr) == "yara") {
				containerType = CONTAINER_TYPE_YARA;
			}
			else {
				throw std::runtime_error("Invalid Container Type");
			}

			m_extensibility.push_back(containerType);
		}
	}
	else {
		throw std::runtime_error("ExtensibilitySelected was not set in the the configuration");
	}
}

/// @brief Get the scanner exclusions from the configuration file
void Configuration::GetScannerExclusions()
{
	if (m_data["Exclusions"].is_array()) {
		m_exclusions = m_data["Exclusions"].template get<std::vector<std::string>>();
	}
	else {
		throw std::runtime_error("Exclusions was not set in the the configuration");
	}
}

/// @brief Get the ignore driver from the configuration file
void Configuration::GetIgnoreDriver() {
	if (m_data["IgnoreDriver"].is_boolean()) {
		m_ignoreDriver = m_data["IgnoreDriver"].template get<bool>();
	}
	else {
		throw std::runtime_error("IgnoreDriver was not set in the the configuration");
	}
}

/// @brief Get the quarantine malicious files from the configuration file
void Configuration::GetQuarantineMaliciousFiles() {
	if (m_data["QuarantineMaliciousFiles"].is_boolean()) {
		m_quartine = m_data["QuarantineMaliciousFiles"].template get<bool>();
	}
	else {
		throw std::runtime_error("QuarantineMaliciousFiles was not set in the the configuration");
	}
}

/// @brief Get the keys from the configuration file
/// @return A vector of strings containing the keys
std::vector<std::string> Configuration::GetJsonKeys() {
	std::vector<std::string> keys;
	if (m_data.is_object()) {
		for (nlohmann::json::const_iterator it = m_data.begin(); it != m_data.end(); ++it) {
			keys.push_back(it.key());
		}
	}
	else {
		throw std::runtime_error("The json data object was not set");
	}

	return keys;
}