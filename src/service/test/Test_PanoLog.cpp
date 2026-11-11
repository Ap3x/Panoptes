#include "gtest/gtest.h"
#include "pano_log.h"
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

// A fresh empty folder for one test, removed afterwards
class LogFolder : public ::testing::Test {
protected:
	void SetUp() override {
		m_folder = fs::temp_directory_path() / ("Test_PanoLog_" + std::to_string(GetCurrentProcessId()) +
			"_" + ::testing::UnitTest::GetInstance()->current_test_info()->name());
		fs::remove_all(m_folder);
		fs::create_directories(m_folder);
	}
	void TearDown() override {
		fs::remove_all(m_folder);
	}
	void Touch(const wchar_t* name) {
		std::ofstream(m_folder / name).put('x');
	}
	DWORD Newest() {
		return NewestLogFileNumber(m_folder.wstring() + L"\\", L"pano", L".log");
	}
	fs::path m_folder;
};

TEST_F(LogFolder, EmptyFolderStartsAtZero) {
	EXPECT_EQ(Newest(), 0u);
}

TEST_F(LogFolder, MissingFolderStartsAtZero) {
	EXPECT_EQ(NewestLogFileNumber(m_folder.wstring() + L"\\missing\\", L"pano", L".log"), 0u);
}

TEST_F(LogFolder, OnlyTheFirstFile) {
	Touch(L"pano.log");
	EXPECT_EQ(Newest(), 0u);
}

TEST_F(LogFolder, HighestNumberNotLastAlphabetically) {
	Touch(L"pano.log");
	Touch(L"pano1.log");
	Touch(L"pano2.log");
	Touch(L"pano10.log");
	EXPECT_EQ(Newest(), 10u);
}

TEST_F(LogFolder, OtherNamesAreIgnored) {
	Touch(L"pano3.log");
	Touch(L"pano99.log.bak");
	Touch(L"panoX7.log");
	Touch(L"pano.old.log");
	Touch(L"detection50.log");
	Touch(L"pano12345678901.log"); // too many digits for a file number
	EXPECT_EQ(Newest(), 3u);
}

TEST_F(LogFolder, CaseInsensitive) {
	Touch(L"PANO4.LOG");
	EXPECT_EQ(Newest(), 4u);
}
