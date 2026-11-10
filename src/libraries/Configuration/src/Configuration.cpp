#include <Windows.h>
#include "Configuration.hpp"
#include "ResourceCore.h"
// #include "panoptes.pb.h"
#include <vector>
#include <sstream>
#include <algorithm>
#include <cctype>

#pragma region Path Patterns

static std::string NormalizeSeparators(std::string path)
{
	std::replace(path.begin(), path.end(), '/', '\\');
	return path;
}

static std::vector<std::string> NormalizePatterns(std::vector<std::string> patterns)
{
	for (auto& pattern : patterns) {
		pattern = NormalizeSeparators(pattern);
	}
	return patterns;
}

static bool CharEqualsIgnoreCase(char a, char b)
{
	return std::tolower((unsigned char)a) == std::tolower((unsigned char)b);
}

// Matches the whole of text against a pattern of literal characters, * and ?. On a mismatch
// it backtracks to the most recent * and lets it absorb one more character
static bool WildcardMatch(const std::string& pattern, const std::string& text)
{
	size_t p = 0;
	size_t t = 0;
	size_t star = std::string::npos;
	size_t starText = 0;

	while (t < text.size()) {
		if (p < pattern.size() && pattern[p] == '*') {
			star = p++;
			starText = t;
		}
		else if (p < pattern.size() && (pattern[p] == '?' || CharEqualsIgnoreCase(pattern[p], text[t]))) {
			p++;
			t++;
		}
		else if (star != std::string::npos) {
			p = star + 1;
			t = ++starText;
		}
		else {
			return false;
		}
	}

	while (p < pattern.size() && pattern[p] == '*') {
		p++;
	}
	return p == pattern.size();
}

bool Configuration::IsPathInList(const std::vector<std::string>& patterns, const std::string& path)
{
	std::string normalizedPath = NormalizeSeparators(path);

	for (const auto& pattern : patterns) {
		if (pattern.empty()) {
			continue;
		}

		if (pattern.find_first_of("*?") != std::string::npos) {
			if (WildcardMatch(pattern, normalizedPath)) {
				return true;
			}
		}
		else if (normalizedPath.size() >= pattern.size() &&
			_strnicmp(normalizedPath.c_str(), pattern.c_str(), pattern.size()) == 0) {
			return true;
		}
	}
	return false;
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
	GetScannerExclusions();
	GetQuarantineMaliciousFiles();
	GetLogExclusions();
	GetDontInject();
	GetFileEvents();
}

/// @brief Check if the configuration file is valid
void Configuration::IsValidJson()
{
	m_data = nlohmann::json::parse(m_fileStream);
}

/// @brief Check that each setting has the right type, after IsValidJson
void Configuration::ValidateSettings()
{
	GetScannerExclusions();
	GetQuarantineMaliciousFiles();
	GetLogExclusions();
	GetDontInject();
	GetFileEvents();
}

const std::vector<std::string>& Configuration::FileEventNames()
{
	// The service maps each one to a PANO_FILE_EVENT_GROUP bit (driver.cpp)
	static const std::vector<std::string> names = {
		"Create",             // files created, overwritten or superseded
		"Write",              // one FileModified event per handle that wrote
		"DeleteRename",       // deletes (including delete-on-close) and renames
		"PipeMailslot",       // named pipe and mailslot creates and opens
		"Security",           // security descriptor (permission/owner) changes
		"ExtendedAttributes"  // extended attribute writes
	};
	return names;
}

/// @brief Get the optional list of file event groups the driver reports
void Configuration::GetFileEvents() {
	if (!m_data.contains("FileEvents")) {
		m_fileEvents = FileEventNames();
		return;
	}

	if (!m_data["FileEvents"].is_array()) {
		throw std::runtime_error("FileEvents must be an array of event group names");
	}

	const auto& valid = FileEventNames();
	std::vector<std::string> names = m_data["FileEvents"].template get<std::vector<std::string>>();
	for (const auto& name : names) {
		if (std::find(valid.begin(), valid.end(), name) == valid.end()) {
			std::string list;
			for (const auto& validName : valid) {
				list += (list.empty() ? "" : ", ") + validName;
			}
			throw std::runtime_error("Unknown FileEvents entry \"" + name + "\". Valid entries: " + list);
		}
	}
	m_fileEvents = names;
}

/// @brief Get the scanner exclusions from the configuration file
void Configuration::GetScannerExclusions()
{
	if (m_data["Exclusions"].is_array()) {
		m_exclusions = NormalizePatterns(m_data["Exclusions"].template get<std::vector<std::string>>());
	}
	else {
		throw std::runtime_error("Exclusions was not set in the the configuration");
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

/// @brief Get the optional log exclusions from the configuration file
void Configuration::GetLogExclusions() {
	if (!m_data.contains("LogExclusions")) {
		return;
	}

	if (m_data["LogExclusions"].is_array()) {
		m_logExclusions = NormalizePatterns(m_data["LogExclusions"].template get<std::vector<std::string>>());
	}
	else {
		throw std::runtime_error("LogExclusions must be an array of paths");
	}
}

/// @brief Get the optional list of process image names the hook DLL is not injected into
void Configuration::GetDontInject() {
	if (!m_data.contains("DontInject")) {
		return;
	}

	if (!m_data["DontInject"].is_array()) {
		throw std::runtime_error("DontInject must be an array of process image names");
	}

	std::vector<std::string> names = NormalizePatterns(m_data["DontInject"].template get<std::vector<std::string>>());
	for (const auto& name : names) {
		if (name.empty()) {
			throw std::runtime_error("DontInject entries must not be empty");
		}
		if (name.find_first_of("*?") != std::string::npos) {
			throw std::runtime_error("DontInject entries do not support wildcards: \"" + name + "\"");
		}
		if (name.find('\\') == std::string::npos) {
			continue; // A file name, matched in any folder
		}

		// A full path. The service converts the drive letter to the NT device the driver sees,
		// so it must be an absolute path on a drive letter: C:\Folder\app.exe
		bool absoluteDrivePath = name.size() > 3 && std::isalpha((unsigned char)name[0]) &&
			name[1] == ':' && name[2] == '\\' && name.back() != '\\';
		if (!absoluteDrivePath) {
			throw std::runtime_error("DontInject entries must be a file name such as \"msedge.exe\" or a full path such as \"C:\\\\Tools\\\\app.exe\": \"" + name + "\"");
		}
	}
	m_dontInject = names;
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