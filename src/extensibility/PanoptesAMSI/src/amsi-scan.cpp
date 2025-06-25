#include "PanoptesAMSI.h"
#include <Shlwapi.h>
#include <amsi.h>

/// @brief Scan a file using Windows built in AMSI feature set
/// @param file_path The path of the file to scan
/// @param copy_path The path to copy the file to, if empty the file will not be copied
/// @param amsi_result The result of the scan, will be set to the result of the scan	
/// @return The result of the scan
HRESULT AmsiScanner::AmsiScanFile(std::string file_path, std::string copy_path, int* amsi_result)
{
	LPWSTR message{};
	HAMSICONTEXT amsiContext = nullptr;
	HAMSISESSION amsiSession = nullptr;
	std::string copy_path_destination;

	if (copy_path != "") {
		LPCSTR baseName = PathFindFileNameA(file_path.c_str());
		copy_path_destination = copy_path + baseName;
		CopyFileA(file_path.c_str(), copy_path_destination.c_str(), false);
	}
	else {
		copy_path_destination = file_path;
	}

	HRESULT hr = AmsiInitialize(L"Panoptes Scanner", &amsiContext);
	if (FAILED(hr))
	{
		return HRESULT_FROM_WIN32(GetLastError());
	}

	hr = AmsiOpenSession(amsiContext, &amsiSession);
	if (FAILED(hr))
	{
		AmsiUninitialize(amsiContext);
		return HRESULT_FROM_WIN32(GetLastError());
	}

	// Check if file exist
	DWORD dwFileAttributes = GetFileAttributesA(copy_path_destination.c_str());
	if (dwFileAttributes == INVALID_FILE_ATTRIBUTES) {
		return HRESULT_FROM_WIN32(GetLastError());
	}

	HANDLE fileHandle = CreateFileA(copy_path_destination.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (fileHandle == INVALID_HANDLE_VALUE)
	{
		AmsiUninitialize(amsiContext);
		return HRESULT_FROM_WIN32(GetLastError());
	}

	DWORD fileSize = GetFileSize(fileHandle, nullptr);
	if (fileSize == INVALID_FILE_SIZE)
	{
		CloseHandle(fileHandle);
		AmsiUninitialize(amsiContext);
		return HRESULT_FROM_WIN32(GetLastError());
	}

	LPVOID fileBuffer = VirtualAlloc(nullptr, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (fileBuffer == nullptr)
	{
		CloseHandle(fileHandle);
		AmsiUninitialize(amsiContext);
		return HRESULT_FROM_WIN32(GetLastError());
	}

	DWORD bytesRead;
	if (!ReadFile(fileHandle, fileBuffer, fileSize, &bytesRead, nullptr))
	{
		VirtualFree(fileBuffer, 0, MEM_RELEASE);
		CloseHandle(fileHandle);
		AmsiUninitialize(amsiContext);
		return HRESULT_FROM_WIN32(GetLastError());
	}

	const int MAX_RETRIES = 3;
	const int RETRY_DELAY_MS = 1000;
	int retryCount = 0;
	AMSI_RESULT result;

	do
	{
		hr = AmsiScanBuffer(amsiContext, fileBuffer, fileSize, nullptr, amsiSession, &result);
		if (FAILED(hr))
		{
			if (hr == HRESULT_FROM_WIN32(ERROR_NOT_READY) && retryCount < MAX_RETRIES)
			{
				retryCount++;
				Sleep(RETRY_DELAY_MS);
			}
			else
			{
				break;
			}
		}
		else {
			*amsi_result = result;
			VirtualFree(fileBuffer, 0, MEM_RELEASE);
			CloseHandle(fileHandle);
			AmsiUninitialize(amsiContext);
			return S_OK;

		}
	} while (FAILED(hr) && retryCount < MAX_RETRIES);

	VirtualFree(fileBuffer, 0, MEM_RELEASE);
	CloseHandle(fileHandle);
	AmsiUninitialize(amsiContext);
	return E_FAIL;
}