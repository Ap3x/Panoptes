#pragma once
#include <string>
#include <fstream>
#include <vector>
#include <nlohmann/json.hpp>

class Configuration {
protected:
	nlohmann::json m_data;
	std::ifstream m_fileStream;

	/// @brief Get the extensibility selected from the configuration file
	void GetExtensibilitySelected();

	/// @brief Get the scanner exclusions from the configuration file
	void GetScannerExclusions();

	/// @brief Get the ignore driver from the configuration file
	void GetIgnoreDriver();

	/// @brief Get the quarantine malicious files from the configuration file
	void GetQuarantineMaliciousFiles();

	/// @brief Get the event providers from the configuration file
	void GetEventProviders();

public:
	/// @brief The type of container that the extensibility is running in
	enum ContainerType : int {
	  CONTAINER_TYPE_NONE = 0,
	  CONTAINER_TYPE_AMSI = 10,
	  CONTAINER_TYPE_PE = 20,
	  CONTAINER_TYPE_YARA = 30
	};

	/// @brief The exclusions from the configuration file
	std::vector<std::string> m_exclusions;

	/// @brief The extensibility selected from the configuration file
	std::vector<Configuration::ContainerType> m_extensibility;

	/// @brief The list of extensibility names from the configuration file
	std::vector<std::string> m_extensibilityListName;

	/// @brief The event providers from the configuration file
	std::vector <std::tuple<std::string, unsigned long, unsigned long>> m_eventProviders;

	/// @brief The ignore driver from the configuration file
	bool m_ignoreDriver = false;

	/// @brief The quarantine malicious files from the configuration file
	bool m_quartine = false;

	/// @brief Constructor for the Configuration class
	/// @param configurationPath The path to the configuration file
	Configuration(std::string configurationPath);

	/// @brief Parse the configuration file
	void Parse();

	/// @brief Check if the configuration file is valid
	void IsValidJson();

	/// @brief Get the keys from the configuration file
	/// @return A vector of strings containing the keys
	std::vector<std::string> GetJsonKeys();
};