#include "hash.h"
#include <wincrypt.h>

/// @brief Generate an MD5 hash of a file using the Windows Crypto API 
/// https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--creating-an-md-5-hash-from-file-content
/// @param filePath The path to the file to hash
/// @return The MD5 hash of the file
std::string GenerateMD5(std::string filePath)
{
	if (filePath.empty())
	{
		return "";
	}
	WCHAR fileHash[33];
	HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return "";
	}

	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	BYTE rgbHash[16];
	DWORD cbHash = 0;
	WCHAR rgbDigits[] = L"0123456789abcdef";

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) ||
		!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
		CloseHandle(hFile);
		return "";
	}

	BYTE rgbFile[1024];
	DWORD bytesRead = 0;
	while (ReadFile(hFile, rgbFile, sizeof(rgbFile), &bytesRead, NULL)) {
		if (bytesRead == 0) break;
		if (!CryptHashData(hHash, rgbFile, bytesRead, 0)) {
			CryptReleaseContext(hProv, 0);
			CryptDestroyHash(hHash);
			CloseHandle(hFile);
			return "";
		}
	}

	cbHash = 16;
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
		for (DWORD i = 0; i < cbHash; i++) {
			fileHash[i * 2] = rgbDigits[rgbHash[i] >> 4];
			fileHash[i * 2 + 1] = rgbDigits[rgbHash[i] & 0xf];
		}
		fileHash[32] = L'\0';
	}

	int size_needed = WideCharToMultiByte(CP_UTF8, 0, fileHash, -1, NULL, 0, NULL, NULL);
	std::string result(size_needed, 0);
	WideCharToMultiByte(CP_UTF8, 0, fileHash, -1, &result[0], size_needed, NULL, NULL);
	std::string test = std::string(result.begin(), result.end());
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CloseHandle(hFile);
	return result;
}
