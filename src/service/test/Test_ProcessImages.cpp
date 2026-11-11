#include "gtest/gtest.h"
#include "process_images.h"

// FILETIME a number of seconds after an arbitrary base
static FILETIME At(double seconds) {
	ULONGLONG value = 134070000000000000ULL + (ULONGLONG)(seconds * 10000000.0);
	FILETIME time;
	time.dwLowDateTime = (DWORD)(value & 0xFFFFFFFF);
	time.dwHighDateTime = (DWORD)(value >> 32);
	return time;
}

// Each test uses its own PIDs: the cache is process-wide

TEST(ProcessImages, ImageIsKnownAfterTheProcessExits) {
	RecordProcessStart(900001, R"(\??\C:\Tests\Test_NtWriteVirtualMemoryx64.exe)", At(0));
	RecordProcessExit(900001);
	// A hook event from just before the exit, delivered after it
	EXPECT_EQ(LookupProcessImage(900001, At(0.5)), R"(C:\Tests\Test_NtWriteVirtualMemoryx64.exe)");
}

TEST(ProcessImages, SystemRootPathsBecomeWin32Paths) {
	RecordProcessStart(900002, R"(\SystemRoot\System32\Conhost.exe)", At(0));
	char windows[MAX_PATH];
	UINT length = GetWindowsDirectoryA(windows, MAX_PATH);
	EXPECT_EQ(LookupProcessImage(900002, At(1)), std::string(windows, length) + R"(\System32\Conhost.exe)");
}

TEST(ProcessImages, ReusedPidResolvesByEventTime) {
	RecordProcessStart(900003, R"(C:\old.exe)", At(0));
	RecordProcessExit(900003);
	RecordProcessStart(900003, R"(C:\new.exe)", At(10));
	EXPECT_EQ(LookupProcessImage(900003, At(5)), R"(C:\old.exe)"); // late event from the old process
	EXPECT_EQ(LookupProcessImage(900003, At(11)), R"(C:\new.exe)");
}

TEST(ProcessImages, SmallClockDifferenceStillMatches) {
	// The hook's timestamp can read slightly earlier than the kernel's creation time
	RecordProcessStart(900004, R"(C:\a.exe)", At(5));
	EXPECT_EQ(LookupProcessImage(900004, At(4.5)), R"(C:\a.exe)");
	EXPECT_EQ(LookupProcessImage(900004, At(2)), "");
}

TEST(ProcessImages, UnknownProcessIsEmpty) {
	EXPECT_EQ(LookupProcessImage(900005, At(0)), "");
}

TEST(ProcessImages, ResolveFallsBackToWindowsForRunningProcesses) {
	// This process started before anything recorded it
	std::string image = ResolveProcessImage(GetCurrentProcessId(), At(0));
	EXPECT_NE(image.find("Test_Service.exe"), std::string::npos) << image;
}
