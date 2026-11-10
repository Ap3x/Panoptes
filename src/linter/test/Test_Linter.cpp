#include "gtest/gtest.h"
#include "Configuration.hpp"
#include <Windows.h>
#include <fstream>

static bool Matches(const std::string& pattern, const std::string& path) {
	return Configuration::IsPathInList({ pattern }, path);
}

TEST(IsPathInList, PatternWithoutWildcardMatchesPrefix) {
	EXPECT_TRUE(Matches("C:\\Windows", "C:\\Windows\\System32\\notepad.exe"));
	EXPECT_TRUE(Matches("C:\\Windows\\", "C:\\Windows\\System32\\notepad.exe"));
	EXPECT_FALSE(Matches("C:\\Windows\\", "C:\\Users\\notepad.exe"));
}

TEST(IsPathInList, PrefixWithoutTrailingSeparatorMatchesSiblings) {
	// Documented behavior: end a prefix with \ to match only inside that folder
	EXPECT_TRUE(Matches("C:\\Foo", "C:\\FooBar\\a.exe"));
	EXPECT_FALSE(Matches("C:\\Foo\\", "C:\\FooBar\\a.exe"));
}

TEST(IsPathInList, MatchingIgnoresCase) {
	EXPECT_TRUE(Matches("c:\\windows\\", "C:\\WINDOWS\\System32\\a.dll"));
	EXPECT_TRUE(Matches("*.DB-WAL", "C:\\data\\cache.db-wal"));
}

TEST(IsPathInList, StarMatchesAnyRunIncludingSeparators) {
	EXPECT_TRUE(Matches("C:\\Users\\*\\AppData\\Local\\ConnectedDevicesPlatform\\*",
		"C:\\Users\\Development\\AppData\\Local\\ConnectedDevicesPlatform\\L.Development\\ActivitiesCache.db-wal"));
	EXPECT_TRUE(Matches("*.db-wal", "C:\\Users\\Development\\AppData\\Local\\x\\y.db-wal"));
	EXPECT_TRUE(Matches("*\\AppData\\Local\\Packages\\*\\LocalState\\*",
		"C:\\Users\\Development\\AppData\\Local\\Packages\\Microsoft.Windows.Photos\\LocalState\\a.db"));
}

TEST(IsPathInList, WildcardPatternMustMatchWholePath) {
	// Without a trailing *, a wildcard pattern does not match deeper paths
	EXPECT_FALSE(Matches("C:\\Users\\*\\AppData", "C:\\Users\\Development\\AppData\\Local\\a.txt"));
	EXPECT_FALSE(Matches("*.db-wal", "C:\\data\\cache.db-wal.bak"));
	EXPECT_FALSE(Matches("*.db-wal", "C:\\data\\cache.db"));
}

TEST(IsPathInList, QuestionMarkMatchesOneCharacter) {
	EXPECT_TRUE(Matches("C:\\logs\\pano?.log", "C:\\logs\\pano7.log"));
	EXPECT_FALSE(Matches("C:\\logs\\pano?.log", "C:\\logs\\pano.log"));
	EXPECT_FALSE(Matches("C:\\logs\\pano?.log", "C:\\logs\\pano42.log"));
}

TEST(IsPathInList, StarBacktracksPastEarlyMatches) {
	EXPECT_TRUE(Matches("*\\cache\\*.tmp", "C:\\cache\\x\\cache\\y.tmp"));
	EXPECT_TRUE(Matches("*a*b*c", "xxaxxbxxbxxc"));
	EXPECT_FALSE(Matches("*a*b*c", "xxaxxbxxbxx"));
}

TEST(IsPathInList, ForwardSlashesInPathMatchBackslashes) {
	EXPECT_TRUE(Matches("C:\\Windows\\", "C:/Windows/System32/a.dll"));
}

TEST(IsPathInList, EmptyListAndEmptyPatternsMatchNothing) {
	EXPECT_FALSE(Configuration::IsPathInList({}, "C:\\a.exe"));
	EXPECT_FALSE(Configuration::IsPathInList({ "" }, "C:\\a.exe"));
}

TEST(IsPathInList, AnyPatternInListCanMatch) {
	std::vector<std::string> patterns = { "C:\\Windows\\", "*.db-wal" };
	EXPECT_TRUE(Configuration::IsPathInList(patterns, "D:\\x.db-wal"));
	EXPECT_TRUE(Configuration::IsPathInList(patterns, "C:\\Windows\\a.dll"));
	EXPECT_FALSE(Configuration::IsPathInList(patterns, "D:\\x.exe"));
}

// The configuration shipped in assets/panoptes.config, checked against real paths
class ShippedConfiguration : public ::testing::Test {
protected:
	static void SetUpTestSuite() {
		s_config = new Configuration(PANOPTES_SHIPPED_CONFIG);
		s_config->Parse();
	}
	static void TearDownTestSuite() {
		delete s_config;
		s_config = nullptr;
	}
	static bool LogExcluded(const std::string& path) {
		return Configuration::IsPathInList(s_config->m_logExclusions, path);
	}
	static bool ScanExcluded(const std::string& path) {
		return Configuration::IsPathInList(s_config->m_exclusions, path);
	}
	static const std::vector<const std::vector<std::string>*> Lists() {
		return { &s_config->m_exclusions, &s_config->m_logExclusions };
	}
	static Configuration* s_config;
};
Configuration* ShippedConfiguration::s_config = nullptr;

TEST_F(ShippedConfiguration, PatternsHaveNoControlCharacters) {
	// e.g. "source\repos" in JSON is "source", a carriage return, then "epos": it matches nothing
	for (const auto* list : Lists()) {
		for (const auto& pattern : *list) {
			for (char c : pattern) {
				EXPECT_GE((unsigned char)c, 0x20) << "control character in pattern: " << pattern;
			}
		}
	}
}

TEST_F(ShippedConfiguration, WildcardPatternsDoNotEndWithSeparator) {
	// A pattern with * must match the whole path, so one ending in \ only matches the folder
	// itself, never the files in it. It should end in \* instead
	for (const auto* list : Lists()) {
		for (const auto& pattern : *list) {
			if (pattern.find_first_of("*?") != std::string::npos) {
				EXPECT_NE(pattern.back(), '\\') << "wildcard pattern only matches a folder: " << pattern;
			}
		}
	}
}

TEST_F(ShippedConfiguration, NoDuplicatePatterns) {
	for (const auto* list : Lists()) {
		for (size_t i = 0; i < list->size(); i++) {
			for (size_t j = i + 1; j < list->size(); j++) {
				EXPECT_NE(_stricmp((*list)[i].c_str(), (*list)[j].c_str()), 0) << "duplicate pattern: " << (*list)[i];
			}
		}
	}
}

TEST_F(ShippedConfiguration, NoisyPathsAreNotLogged) {
	EXPECT_TRUE(LogExcluded("C:\\Users\\Development\\AppData\\Local\\ConnectedDevicesPlatform\\L.Development\\ActivitiesCache.db"));
	EXPECT_TRUE(LogExcluded("C:\\Windows\\System32\\winevt\\Logs\\System.evtx"));
	EXPECT_TRUE(LogExcluded("C:\\Windows\\Prefetch\\NOTEPAD.EXE-D8414F97.pf"));
	EXPECT_TRUE(LogExcluded("C:\\Windows\\System32\\config\\SOFTWARE.LOG1"));
	EXPECT_TRUE(LogExcluded("C:\\Windows\\System32\\LogFiles\\WMI\\RtBackup\\EtwRTEventLog-System.etl"));
	EXPECT_TRUE(LogExcluded("C:\\Users\\Development\\AppData\\Local\\Comms\\UnistoreDB\\store.vol"));
	EXPECT_TRUE(LogExcluded("C:\\Users\\Development\\AppData\\Local\\Comms\\Unistore\\data\\0\\a.dat"));
	EXPECT_TRUE(LogExcluded("C:\\Users\\Development\\AppData\\Local\\Packages\\Microsoft.Windows.Search_cw5n1h2txyewy\\LocalState\\a.dat"));
	EXPECT_TRUE(LogExcluded("C:\\Users\\Development\\AppData\\Local\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat"));
	EXPECT_TRUE(LogExcluded("C:\\Users\\Development\\AppData\\Local\\Microsoft\\Windows\\Explorer\\iconcache_16.db"));
	EXPECT_TRUE(LogExcluded("C:\\Users\\Development\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData\\ABCDEF"));
	EXPECT_TRUE(LogExcluded("C:\\Users\\Development\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"));
	EXPECT_TRUE(LogExcluded("C:\\Users\\Development\\AppData\\Local\\Microsoft\\OneDrive\\logs\\ListSync\\Business1\\a.odl"));
	EXPECT_TRUE(LogExcluded("C:\\Users\\Development\\AppData\\Local\\Microsoft\\OneDrive\\logs\\Common\\a.odl"));
	EXPECT_TRUE(LogExcluded("C:\\Users\\Development\\ntuser.dat.LOG2"));
	EXPECT_TRUE(LogExcluded("C:\\Windows\\ServiceProfiles\\NetworkService\\NTUSER.DAT"));
	EXPECT_TRUE(LogExcluded("C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Logs\\a.etl"));
	EXPECT_TRUE(LogExcluded("C:\\Windows\\ServiceState\\EventLog\\Data\\lastalive0.dat"));
	EXPECT_TRUE(LogExcluded("C:\\ProgramData\\Microsoft\\Windows Defender\\Support\\MPLog-1.log"));
	EXPECT_TRUE(LogExcluded("C:\\ProgramData\\Microsoft\\Diagnosis\\ETLLogs\\a.etl"));
	EXPECT_TRUE(LogExcluded("C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb"));
	EXPECT_TRUE(LogExcluded("C:\\Windows\\System32\\UserMgrLog.etl"));
	EXPECT_TRUE(LogExcluded("C:\\$Recycle.Bin\\S-1-5-21-1\\$RABC.txt"));
	EXPECT_TRUE(LogExcluded("C:\\Windows\\Logs\\CBS\\CBS.log"));
	EXPECT_TRUE(LogExcluded("C:\\Windows\\System32\\sru\\SRUDB.dat"));
	EXPECT_TRUE(LogExcluded("C:\\Windows\\SoftwareDistribution\\DataStore\\Logs\\edb.log"));
	// Matching ignores case
	EXPECT_TRUE(LogExcluded("c:\\windows\\prefetch\\cmd.exe-1.pf"));
}

TEST_F(ShippedConfiguration, InterestingPathsAreStillLogged) {
	EXPECT_FALSE(LogExcluded("C:\\Users\\Development\\Desktop\\payload.exe"));
	EXPECT_FALSE(LogExcluded("C:\\Users\\Development\\Downloads\\invoice.pdf.exe"));
	EXPECT_FALSE(LogExcluded("C:\\Users\\Development\\AppData\\Local\\Temp\\dropper.dll"));
	EXPECT_FALSE(LogExcluded("C:\\Users\\Development\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\run.lnk"));
	EXPECT_FALSE(LogExcluded("C:\\ProgramData\\evil.dll"));
	EXPECT_FALSE(LogExcluded("C:\\Windows\\System32\\notepad.exe"));
	EXPECT_FALSE(LogExcluded("C:\\Windows\\Temp\\a.exe"));
	EXPECT_FALSE(LogExcluded("C:\\Users\\Development\\ntuser.dat"));
}

TEST_F(ShippedConfiguration, ScanExclusions) {
	EXPECT_TRUE(ScanExcluded("C:\\Windows\\System32\\notepad.exe"));
	EXPECT_TRUE(ScanExcluded("C:\\Program Files\\Microsoft Visual Studio\\18\\Community\\Common7\\IDE\\devenv.exe"));
	EXPECT_TRUE(ScanExcluded("C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\156.0.4314.50\\msedgewebview2.exe"));
	EXPECT_TRUE(ScanExcluded("C:\\Users\\Research\\source\\repos\\Panoptes\\bin\\a.exe"));
	EXPECT_TRUE(ScanExcluded("C:\\Users\\Development\\AppData\\Local\\Packages\\a\\b.dll"));
	EXPECT_FALSE(ScanExcluded("C:\\Users\\Development\\Downloads\\payload.exe"));
	EXPECT_FALSE(ScanExcluded("C:\\Users\\Development\\AppData\\Local\\Temp\\dropper.dll"));
	EXPECT_FALSE(ScanExcluded("C:\\Program Files\\SomeVendor\\app.exe"));
}


TEST_F(ShippedConfiguration, DontInjectNamesAreUniqueFileNames) {
	// Parse rejects paths and wildcards; the driver compares names without regard to case
	const auto& names = s_config->m_dontInject;
	EXPECT_FALSE(names.empty());
	for (size_t i = 0; i < names.size(); i++) {
		for (size_t j = i + 1; j < names.size(); j++) {
			EXPECT_NE(_stricmp(names[i].c_str(), names[j].c_str()), 0) << "duplicate DontInject name: " << names[i];
		}
	}
}

// Parses a minimal configuration plus extraMembers (JSON object members, e.g.
// "\"DontInject\": []", or empty) and returns the requested list from it
static std::vector<std::string> ParseConfigList(const std::string& extraMembers, std::vector<std::string> Configuration::* list) {
	char tempDir[MAX_PATH];
	char tempFile[MAX_PATH];
	GetTempPathA(MAX_PATH, tempDir);
	GetTempFileNameA(tempDir, "pno", 0, tempFile);
	{
		std::ofstream out(tempFile);
		out << "{\"Exclusions\": [], \"QuarantineMaliciousFiles\": false";
		if (!extraMembers.empty()) {
			out << ", " << extraMembers;
		}
		out << "}";
	}

	std::vector<std::string> result;
	try {
		Configuration config(tempFile);
		config.Parse();
		result = config.*list;
	}
	catch (...) {
		DeleteFileA(tempFile);
		throw;
	}
	DeleteFileA(tempFile);
	return result;
}

static std::vector<std::string> ParseDontInject(const std::string& dontInjectJson) {
	return ParseConfigList("\"DontInject\": " + dontInjectJson, &Configuration::m_dontInject);
}

static std::vector<std::string> ParseFileEvents(const std::string& fileEventsJson) {
	return ParseConfigList(fileEventsJson.empty() ? "" : "\"FileEvents\": " + fileEventsJson, &Configuration::m_fileEvents);
}

TEST(FileEvents, DefaultsToEveryGroup) {
	EXPECT_EQ(ParseFileEvents(""), Configuration::FileEventNames());
}

TEST(FileEvents, AcceptsKnownGroups) {
	auto groups = ParseFileEvents(R"(["Create", "Security"])");
	EXPECT_EQ(groups, (std::vector<std::string>{ "Create", "Security" }));
	EXPECT_TRUE(ParseFileEvents("[]").empty()); // every group off
}

TEST(FileEvents, RejectsUnknownGroupsAndNonArrays) {
	EXPECT_THROW(ParseFileEvents(R"(["Reads"])"), std::runtime_error);
	EXPECT_THROW(ParseFileEvents(R"(["create"])"), std::runtime_error); // names are case-sensitive
	EXPECT_THROW(ParseFileEvents(R"("Create")"), std::runtime_error);
}

TEST_F(ShippedConfiguration, FileEventsEnablesEveryGroup) {
	EXPECT_EQ(s_config->m_fileEvents, Configuration::FileEventNames());
}

TEST(DontInject, AcceptsFileNamesAndFullPaths) {
	// Raw strings hold JSON, so each \\ is one \ in the parsed value
	auto names = ParseDontInject(R"(["msedge.exe", "C:\\Tools\\app.exe", "d:/x/y.exe"])");
	ASSERT_EQ(names.size(), 3u);
	EXPECT_EQ(names[0], "msedge.exe");
	EXPECT_EQ(names[1], "C:\\Tools\\app.exe");
	EXPECT_EQ(names[2], "d:\\x\\y.exe"); // / is normalized to \ like the other path settings
}

TEST(DontInject, RejectsRelativeUncFolderAndWildcardEntries) {
	EXPECT_THROW(ParseDontInject(R"(["Tools\\app.exe"])"), std::runtime_error);
	EXPECT_THROW(ParseDontInject(R"(["\\\\server\\share\\app.exe"])"), std::runtime_error);
	EXPECT_THROW(ParseDontInject(R"(["C:\\Tools\\"])"), std::runtime_error);
	EXPECT_THROW(ParseDontInject(R"(["*.exe"])"), std::runtime_error);
	EXPECT_THROW(ParseDontInject(R"([""])"), std::runtime_error);
	EXPECT_THROW(ParseDontInject(R"("msedge.exe")"), std::runtime_error);
}
