#pragma once
#include <string>
#include <fstream>
#include <vector>
#include <nlohmann/json.hpp>

class Configuration {
protected:
	nlohmann::json m_data;
	std::ifstream m_fileStream;

	/// @brief Get the scanner exclusions from the configuration file
	void GetScannerExclusions();

	/// @brief Get the quarantine malicious files from the configuration file
	void GetQuarantineMaliciousFiles();

	/// @brief Get the optional log exclusions from the configuration file
	void GetLogExclusions();

	/// @brief Get the optional DontInject list from the configuration file
	void GetDontInject();

	/// @brief Get the optional FileEvents list from the configuration file
	void GetFileEvents();

	/// @brief Get the optional EnforceDetectionActions setting from the configuration file
	void GetEnforceDetectionActions();

public:
	/// @brief The names FileEvents accepts, one per group of file system events the driver can
	/// report. When FileEvents is not set, all of them are reported
	static const std::vector<std::string>& FileEventNames();
	/// @brief The type of container that the extensibility is running in
	enum ContainerType : int {
	  CONTAINER_TYPE_NONE = 0,
	  CONTAINER_TYPE_YARA = 30
	};

	/// @brief Path patterns that are not scanned (see IsPathInList)
	std::vector<std::string> m_exclusions;

	/// @brief The quarantine malicious files from the configuration file
	bool m_quartine = false;

	/// @brief Path patterns whose driver events are not logged (see IsPathInList). Files
	/// matching them are still scanned
	std::vector<std::string> m_logExclusions;

	/// @brief Processes the driver does not inject the hook DLL into. Each entry is either a file
	/// name such as "msedge.exe", matching that image in any folder, or a full path such as
	/// "C:\Tools\app.exe" (/ is normalized to \), matching only that image. Compared without
	/// regard to case. Sent to the driver with IOCTL_PANOPTES_SET_INJECTION_EXCLUSIONS when the
	/// service starts
	std::vector<std::string> m_dontInject;

	/// @brief The groups of file system events the driver reports, from FileEventNames(). Every
	/// group if FileEvents is not set. Sent to the driver with IOCTL_PANOPTES_SET_FILE_EVENTS
	/// when the service starts
	std::vector<std::string> m_fileEvents = FileEventNames();

	/// @brief Whether the service carries out the kill and quarantine actions of detector rules.
	/// When false (the default) those detections are logged and notified only
	bool m_enforceDetectionActions = false;

	/// @brief Check whether a path matches any pattern in an exclusion list. A pattern with no
	/// wildcard matches every path that starts with it. A pattern containing * (any run of
	/// characters, including \) or ? (a single character) must match the whole path. Matching
	/// ignores case. / in the path is treated as \; patterns loaded by Parse are normalized
	/// the same way
	static bool IsPathInList(const std::vector<std::string>& patterns, const std::string& path);

	/// @brief Constructor for the Configuration class
	/// @param configurationPath The path to the configuration file
	Configuration(std::string configurationPath);

	/// @brief Parse the configuration file
	void Parse();

	/// @brief Check if the configuration file is valid
	void IsValidJson();

	/// @brief Check that each setting has the right type, after IsValidJson. Throws
	/// std::runtime_error naming the first invalid setting
	void ValidateSettings();

	/// @brief Get the keys from the configuration file
	/// @return A vector of strings containing the keys
	std::vector<std::string> GetJsonKeys();
};