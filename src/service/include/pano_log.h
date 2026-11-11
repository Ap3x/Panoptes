#pragma once
#include <Windows.h>
#include <string>

/// @brief Appends a line to the event log: LOG_FOLDER\pano.log, continuing in pano1.log,
/// pano2.log, ... once a file reaches MAX_FILE_SIZE. On the first write it continues in the
/// newest file already on disk, so a restart neither appends to a full file nor reuses old ones
/// @param message The line, including its newline
void WriteToLogFile(const std::string& message);

/// @brief The number of the newest log file in a folder: 0 for base.ext (or when there is none),
/// N for baseN.ext. Other names, such as base.old.ext or baseX.ext, are ignored
/// @param folder The folder, ending in a backslash
/// @param base The file name before the number, e.g. L"pano"
/// @param ext The extension including the dot, e.g. L".log"
DWORD NewestLogFileNumber(const std::wstring& folder, const std::wstring& base, const std::wstring& ext);
