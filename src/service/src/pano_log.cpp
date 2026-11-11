#include <Windows.h>
#include <sstream>
#include <iostream>
#include <mutex>
#include "service_constants.h"

bool EnsureDirectoryExists(const std::wstring& path) {
    DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        return true; // Directory already exists
    }

    // Recursively create parent directories
    size_t pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        if (!EnsureDirectoryExists(path.substr(0, pos))) {
            return false;
        }
    }

    // Create the directory
    if (!CreateDirectoryW(path.c_str(), NULL)) {
        DWORD error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS) {
            std::wcerr << L"Failed to create directory: " << path << L". Error code: " << error << std::endl;
            return false;
        }
    }

    return true;
}

DWORD NewestLogFileNumber(const std::wstring& folder, const std::wstring& base, const std::wstring& ext) {
    DWORD newest = 0;
    WIN32_FIND_DATAW found;
    HANDLE search = FindFirstFileW((folder + base + L"*" + ext).c_str(), &found);
    if (search == INVALID_HANDLE_VALUE) {
        return 0;
    }
    do {
        std::wstring name = found.cFileName;
        // The wildcard also matches short (8.3) names and longer extensions; check exactly
        if (name.size() <= base.size() + ext.size() ||
            _wcsnicmp(name.c_str(), base.c_str(), base.size()) != 0 ||
            _wcsicmp(name.c_str() + name.size() - ext.size(), ext.c_str()) != 0) {
            continue;
        }
        std::wstring digits = name.substr(base.size(), name.size() - base.size() - ext.size());
        if (digits.size() > 9 || digits.find_first_not_of(L"0123456789") != std::wstring::npos) {
            continue;
        }
        DWORD number = (DWORD)std::stoul(digits);
        if (number > newest) {
            newest = number;
        }
    } while (FindNextFileW(search, &found));
    FindClose(search);
    return newest;
}

// LOG_FOLDER\pano.log for 0, otherwise LOG_FOLDER\panoN.log
static std::wstring LogFilePath(DWORD number) {
    std::wostringstream oss;
    oss << LOG_FOLDER << BASE_FILENAME;
    if (number > 0) {
        oss << number;
    }
    oss << FILE_EXTENSION;
    return oss.str();
}

void WriteToLogFile(const std::string& message) {
    // Called from the driver event threads and the hook event consumer; the lock keeps lines
    // whole and serializes rotating to the next file
    static std::mutex lock;
    std::lock_guard<std::mutex> guard(lock);

    static DWORD currentFileNumber = 0;
    static bool numberFound = false;
    static HANDLE hFile = INVALID_HANDLE_VALUE;
    // Size of the open file, kept here so each write does not have to query it
    static ULONGLONG currentFileSize = 0;

    DWORD bytesWritten = 0;

    if (hFile != INVALID_HANDLE_VALUE && currentFileSize >= MAX_FILE_SIZE) {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
        currentFileNumber++;
    }

    if (hFile == INVALID_HANDLE_VALUE) {
        // Only checked when a file is opened: once one is open, its folder exists
        if (!EnsureDirectoryExists(LOG_FOLDER)) {
            std::wcerr << L"Failed to create log directory" << std::endl;
            return;
        }

        // Continue in the newest file from an earlier run rather than starting over at pano.log,
        // which would append to full files and leave the newest events in an old one
        if (!numberFound) {
            currentFileNumber = NewestLogFileNumber(LOG_FOLDER, BASE_FILENAME, FILE_EXTENSION);
            numberFound = true;
        }

        // The newest file may already be full; then the next number starts a new one
        for (;;) {
            std::wstring fullPath = LogFilePath(currentFileNumber);
            hFile = CreateFileW(
                fullPath.c_str(),
                FILE_APPEND_DATA,  // Every write goes to the end of the file
                FILE_SHARE_READ,
                NULL,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );

            if (hFile == INVALID_HANDLE_VALUE) {
                std::wcerr << L"Failed to open log file: " << fullPath << std::endl;
                return;
            }

            LARGE_INTEGER size;
            currentFileSize = GetFileSizeEx(hFile, &size) ? (ULONGLONG)size.QuadPart : 0;
            if (currentFileSize < MAX_FILE_SIZE) {
                break;
            }
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
            currentFileNumber++;
        }
    }

    if (!WriteFile(hFile, message.c_str(), message.length() * sizeof(char), &bytesWritten, NULL)) {
        std::wcerr << L"Failed to write to log file" << std::endl;
    }
    currentFileSize += bytesWritten;
}