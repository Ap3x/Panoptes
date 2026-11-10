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

void WriteToLogFile(const std::string& message) {
    // Called from the driver event threads and the hook event consumer; the lock keeps lines
    // whole and serializes rotating to the next file
    static std::mutex lock;
    std::lock_guard<std::mutex> guard(lock);

    static DWORD currentFileNumber = 0;
    static HANDLE hFile = INVALID_HANDLE_VALUE;
    // Size of the open file, kept here so each write does not have to query it
    static ULONGLONG currentFileSize = 0;

    std::wstring fullPath;
    DWORD bytesWritten = 0;

    if (hFile == INVALID_HANDLE_VALUE || currentFileSize >= MAX_FILE_SIZE) {
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
            currentFileNumber++;
        }

        // Only checked when a file is opened: once one is open, its folder exists
        if (!EnsureDirectoryExists(LOG_FOLDER)) {
            std::wcerr << L"Failed to create log directory" << std::endl;
            return;
        }

        std::wostringstream oss;
        oss << LOG_FOLDER << BASE_FILENAME;
        if (currentFileNumber > 0) {
            oss << currentFileNumber;
        }
        oss << FILE_EXTENSION;
        fullPath = oss.str();

        hFile = CreateFileW(
            fullPath.c_str(),
            FILE_APPEND_DATA,  // Changed from GENERIC_WRITE to FILE_APPEND_DATA
            FILE_SHARE_READ,
            NULL,
            OPEN_ALWAYS,       // Changed from CREATE_ALWAYS to OPEN_ALWAYS
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            std::wcerr << L"Failed to open log file: " << fullPath << std::endl;
            return;
        }

        // Move file pointer to the end of the file
        SetFilePointer(hFile, 0, NULL, FILE_END);

        LARGE_INTEGER size;
        currentFileSize = GetFileSizeEx(hFile, &size) ? (ULONGLONG)size.QuadPart : 0;
    }

    if (!WriteFile(hFile, message.c_str(), message.length() * sizeof(char), &bytesWritten, NULL)) {
        std::wcerr << L"Failed to write to log file" << std::endl;
    }
    currentFileSize += bytesWritten;
}