#pragma once
#include <Windows.h>
#include <string>
#include <ctime>

bool IsRunningAsAdmin();
bool FileExists(const char* filename);
std::string ToString(const std::wstring& wstr);
std::string ToLower(std::string str);
std::string GetExecutableDirectory();
bool HasCommandLineFlag(const char* flag);
std::string GetBaseName(const std::string& path);
std::string FormatTime(const std::time_t& time);
/// @brief The log's Time format: "2026/11/15 21:05:48.123", in the FILETIME's zone (UTC)
std::string FormatSystemTime(const FILETIME& ft);
