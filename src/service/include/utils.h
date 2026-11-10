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
std::string FormatSystemTime(const FILETIME& ft);
