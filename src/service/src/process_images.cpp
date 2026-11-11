#include "process_images.h"
#include "utils.h"
#include <algorithm>
#include <deque>
#include <mutex>
#include <unordered_map>
#include <vector>

// How long an exited process's image is kept for its late hook events. ETW delivers within
// about a second; this leaves room for a busy machine
#define PANO_IMAGE_KEEP_MS 60000

// Entries kept per PID. Two covers an event from the old process arriving after the PID was
// already reused
#define PANO_IMAGES_PER_PID 2

// The process creation time (kernel clock) and the hook event time (ETW's QPC converted to
// FILETIME) can disagree slightly; an event this far before the recorded start still counts
#define PANO_IMAGE_TIME_SLACK (10000000ULL) // 1 second in 100ns units

struct ProcessImageEntry {
	std::string Image;
	ULONGLONG Start = 0;    // FILETIME as a number
	ULONGLONG ExitTick = 0; // GetTickCount64 when the exit was recorded; 0 while running
};

static std::mutex g_Lock;
static std::unordered_map<DWORD, std::vector<ProcessImageEntry>> g_Images;
// Exits in the order they were recorded, so expired entries are found without a full scan
static std::deque<std::pair<ULONGLONG, DWORD>> g_Exits;

static ULONGLONG ToNumber(const FILETIME& time)
{
	return ((ULONGLONG)time.dwHighDateTime << 32) | time.dwLowDateTime;
}

static bool StartsWithIgnoreCase(const std::string& text, const char* prefix)
{
	size_t length = strlen(prefix);
	return text.size() >= length && _strnicmp(text.c_str(), prefix, length) == 0;
}

// "\??\C:\x.exe" -> "C:\x.exe" and "\SystemRoot\System32\x.exe" -> "C:\Windows\System32\x.exe"
static std::string ToWin32Path(const std::string& image)
{
	if (StartsWithIgnoreCase(image, "\\??\\")) {
		return image.substr(4);
	}
	if (StartsWithIgnoreCase(image, "\\SystemRoot\\")) {
		WCHAR windows[MAX_PATH];
		UINT length = GetWindowsDirectoryW(windows, MAX_PATH);
		if (length > 0 && length < MAX_PATH) {
			return ToString(std::wstring(windows, length)) + image.substr(strlen("\\SystemRoot"));
		}
	}
	return image;
}

// Forgets processes that exited more than PANO_IMAGE_KEEP_MS ago. Called with g_Lock held
static void Prune(ULONGLONG now)
{
	while (!g_Exits.empty() && now - g_Exits.front().first >= PANO_IMAGE_KEEP_MS) {
		DWORD processId = g_Exits.front().second;
		g_Exits.pop_front();

		auto found = g_Images.find(processId);
		if (found == g_Images.end()) {
			continue;
		}
		auto& entries = found->second;
		entries.erase(std::remove_if(entries.begin(), entries.end(), [now](const ProcessImageEntry& entry) {
			return entry.ExitTick != 0 && now - entry.ExitTick >= PANO_IMAGE_KEEP_MS;
		}), entries.end());
		if (entries.empty()) {
			g_Images.erase(found);
		}
	}
}

void RecordProcessStart(DWORD processId, const std::string& image, const FILETIME& time)
{
	std::lock_guard<std::mutex> guard(g_Lock);
	Prune(GetTickCount64());

	auto& entries = g_Images[processId];
	ProcessImageEntry entry;
	entry.Image = ToWin32Path(image);
	entry.Start = ToNumber(time);
	entries.push_back(std::move(entry));
	if (entries.size() > PANO_IMAGES_PER_PID) {
		entries.erase(entries.begin());
	}
}

void RecordProcessExit(DWORD processId)
{
	ULONGLONG now = GetTickCount64();
	std::lock_guard<std::mutex> guard(g_Lock);
	Prune(now);

	auto found = g_Images.find(processId);
	if (found == g_Images.end()) {
		return; // started before the service
	}
	// The newest entry is the process that exited; an older one has already exited
	auto& newest = found->second.back();
	if (newest.ExitTick == 0) {
		newest.ExitTick = now;
		g_Exits.emplace_back(now, processId);
	}
}

std::string LookupProcessImage(DWORD processId, const FILETIME& time)
{
	ULONGLONG at = ToNumber(time);
	std::lock_guard<std::mutex> guard(g_Lock);
	auto found = g_Images.find(processId);
	if (found == g_Images.end()) {
		return "";
	}
	// Newest first: the latest process with this ID that had started by then
	const auto& entries = found->second;
	for (auto entry = entries.rbegin(); entry != entries.rend(); ++entry) {
		if (entry->Start <= at + PANO_IMAGE_TIME_SLACK) {
			return entry->Image;
		}
	}
	return "";
}

std::string ResolveProcessImage(DWORD processId, const FILETIME& time)
{
	std::string image = LookupProcessImage(processId, time);
	if (!image.empty()) {
		return image;
	}

	HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
	if (process == NULL) {
		return "";
	}
	WCHAR path[MAX_PATH * 2];
	DWORD length = ARRAYSIZE(path);
	if (QueryFullProcessImageNameW(process, 0, path, &length)) {
		image = ToString(std::wstring(path, length));
	}
	CloseHandle(process);
	return image;
}
