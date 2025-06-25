#include "utils.h"
#include <algorithm>
#include <Shlwapi.h>
#include <stdexcept>
#include <vector>
#include <sstream>


bool IsRunningAsAdmin() {
	BOOL isAdmin = FALSE;
	PSID adminGroup = NULL;

	// Allocate and initialize a SID of the administrators group.
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (AllocateAndInitializeSid(
		&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&adminGroup)) {
		// Check whether the SID of administrators group is enabled in 
		// the primary access token of the process.
		if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
			isAdmin = FALSE;
		}
		FreeSid(adminGroup);
	}

	return isAdmin != FALSE;
}

bool FileExists(const char* filename) {
	HANDLE hFile = CreateFileA(filename,
		GENERIC_READ,          // Open for reading
		FILE_SHARE_READ,       // Share for reading
		NULL,                  // Default security
		OPEN_EXISTING,         // Open only if exists
		FILE_ATTRIBUTE_NORMAL, // Normal file
		NULL);                 // No template

	if (hFile == INVALID_HANDLE_VALUE) {
		return false;  // File does not exist
	}

	CloseHandle(hFile);
	return true;  // File exists
}

std::string ToString(const std::wstring& wstr)
{
	if (wstr.empty())
	{
		return std::string();
	}
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
	std::string str(size_needed, 0);
	WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str[0], size_needed, NULL, NULL);
	return str;
}

std::string ToLower(std::string str) {
	std::transform(str.begin(), str.end(), str.begin(),
		[](unsigned char c) { return std::tolower(c); });
	return str;
}

std::string GetCurrentPath()
{
	char buffer[MAX_PATH];
	DWORD length = GetCurrentDirectoryA(MAX_PATH, buffer);

	if (length == 0)
	{
		// Handle error - you might want to throw an exception or return an error code
		return "";
	}

	return std::string(buffer);
}

std::string GetBaseName(const std::string& path) {
	const char* fileName = PathFindFileNameA(path.c_str());
	return std::string(fileName);
}

std::string FormatTime(const std::time_t& time) {
	std::tm timeinfo;
	localtime_s(&timeinfo, &time);

	char buffer[80];
	std::strftime(buffer, sizeof(buffer), "%a %b %d %H:%M:%S %Y", &timeinfo);

	return std::string(buffer);
}