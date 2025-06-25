#include <Windows.h>
#include <sstream>
#include <iostream>
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
    static DWORD currentFileNumber = 0;
    static HANDLE hFile = INVALID_HANDLE_VALUE;

    std::wstring fullPath;
    DWORD bytesWritten;

    // Ensure the log directory exists
    if (!EnsureDirectoryExists(LOG_FOLDER)) {
        std::wcerr << L"Failed to create log directory" << std::endl;
        return;
    }

    if (hFile == INVALID_HANDLE_VALUE || GetFileSize(hFile, NULL) >= MAX_FILE_SIZE) {
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
            currentFileNumber++;
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
    }

    if (!WriteFile(hFile, message.c_str(), message.length() * sizeof(char), &bytesWritten, NULL)) {
        std::wcerr << L"Failed to write to log file" << std::endl;
    }
}