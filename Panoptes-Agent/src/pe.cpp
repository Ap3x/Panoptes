#include "pe.hpp"
#include <wchar.h>

VOID ParseCryptIntegerBlob(const CRYPT_INTEGER_BLOB *pIntegerBlob)
{
	DWORD cbData = pIntegerBlob->cbData;
	const BYTE *pbData = pIntegerBlob->pbData;

	// Parse the integer data
	DWORD value = 0;
	for (DWORD i = 0; i < cbData; i++)
	{
		value |= (DWORD)pbData[i] << (8 * i);
	}

	// Use the parsed value as needed
	printf("Parsed value: %ld\n", value);
}

BOOL IsSignerExclusion(LPCWSTR SignerName)
{
	LPCWSTR exclusionList[] =
		{
			L"Google LLC",
			L"Microsoft Corporation",
			L"Microsoft Windows Publisher",
		};

	// No Exclusions Set
	// LPCWSTR exclusionList[] = { 0 };

	if (exclusionList[0] == NULL)
	{
		return false;
	}

	for (int i = 0; i < sizeof(exclusionList) / sizeof(LPCWSTR); i++)
	{
		if (wcsstr(SignerName, exclusionList[i]) != 0)
		{
			// If in Exclusion list then ignore
			return true;
		}
	}
	// If not in exclusion list then continue with checks
	return false;
}

// https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file
BOOL pe::VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
{
	LONG lStatus;
	;
	WINTRUST_FILE_INFO fileInfo = {0};
	WINTRUST_DATA trustData = {0};
	GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
	fileInfo.pcwszFilePath = pwszSourceFile;
	fileInfo.hFile = NULL;
	fileInfo.pgKnownSubject = NULL;

	BYTE *pbCertData = NULL;
	DWORD cbCertData = 0;
	PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		pbCertData,
		cbCertData);

	trustData.cbStruct = sizeof(WINTRUST_DATA);
	trustData.pPolicyCallbackData = NULL;
	trustData.pSIPClientData = NULL;
	trustData.dwUIChoice = WTD_UI_NONE;
	trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	trustData.dwUnionChoice = WTD_CHOICE_FILE;
	trustData.pFile = &fileInfo;
	trustData.dwStateAction = WTD_STATEACTION_VERIFY;
	trustData.hWVTStateData = NULL;
	trustData.pwszURLReference = NULL;
	trustData.dwProvFlags = WTD_SAFER_FLAG;
	trustData.dwUIContext = WTD_UICONTEXT_EXECUTE;

	lStatus = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &policyGUID, &trustData);
	if (SUCCEEDED(lStatus))
	{
		CRYPT_PROVIDER_DATA *pProviderData = WTHelperProvDataFromStateData(trustData.hWVTStateData);
		if (pProviderData && pProviderData->csSigners > 0)
		{
			CRYPT_PROVIDER_SGNR *pProviderSigner = WTHelperGetProvSignerFromChain(pProviderData, 0, FALSE, 0);
			if (pProviderSigner && pProviderSigner->csCertChain > 0)
			{
				CRYPT_PROVIDER_CERT *pProviderCert = WTHelperGetProvCertFromChain(pProviderSigner, 0);
				if (pProviderCert)
				{
					pCertContext = CertDuplicateCertificateContext(pProviderCert->pCert);
					DWORD dwSize = CertGetNameStringW(pCertContext,
													  CERT_NAME_SIMPLE_DISPLAY_TYPE,
													  0,
													  NULL,
													  NULL,
													  0);

					// Allocate a buffer for the subject name string
					LPWSTR pszSubjectName = new WCHAR[dwSize];

					// Retrieve the subject name string
					dwSize = CertGetNameStringW(pCertContext,
												CERT_NAME_SIMPLE_DISPLAY_TYPE,
												0,
												NULL,
												pszSubjectName,
												dwSize);
					if (IsSignerExclusion(pszSubjectName))
					{
						return true;
					}
					return false;
				}
			}
		}
	}

	trustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &policyGUID, &trustData);

	return false;
}

INT pe::CheckForImportFunctions(LPCWSTR PortableExecutablePath)
{
	std::vector<IATEntry> matchingEntries;
	int badScore = 0;
	std::vector<IATEntry> importFunctions;
	GetPEImportFunctions(PortableExecutablePath, &importFunctions);

	if (importFunctions.size() == 0)
	{
		// printf("[!] Something seems fishy\n");
		badScore = -1;
	}
	else
	{
		std::vector<BadImports> badImports = {
			{"KERNEL32", "OpenProcess", 1},
			{"KERNEL32", "VirtualAllocEx", 1},
			{"KERNEL32", "VirtualAlloc", 1},
			{"KERNEL32", "CreateRemoteThread", 2},
			{"KERNEL32", "WriteProcessMemory", 2},
			{"KERNEL32", "GetProcAddress", 2},
			{"KERNEL32", "VirtualAlloc", 2},
			{"KERNEL32", "LoadLibraryA", 2},
			{"KERNEL32", "CreateProcess", 2},
			{"KERNEL32", "VirtualProtect", 2},
			{"KERNEL32", "CreateToolhelp32Snapshot", 2},
			{"KERNEL32", "Process32First", 2},
			{"KERNEL32", "Process32Next", 2},
			{"ADVAPI32", "RegOpenKeyEx", 2},
			{"ADVAPI32", "RegSetValueEx", 2},
			{"ADVAPI32", "RegCreateKeyEx", 2},
			{"ADVAPI32", "RegDeleteValue", 2},
			{"WININET", "InternetOpen", 2},
			{"WININET", "InternetOpenUrl", 2},
			{"WININET", "InternetReadFile", 2},
			{"WININET", "InternetWriteFile", 2},
			{"WSOCK32", "socket", 2},
			{"WSOCK32", "connect", 2},
			{"WSOCK32", "send", 2},
			{"WSOCK32", "recv", 2},
			{"URLMON", "URLDownloadToFile", 2},
			{"SHELL32", "ShellExecute", 2},
			{"SHLWAPI", "PathFileExists", 2},
			{"USER32", "GetAsyncKeyState", 2},
			{"USER32", "GetForegroundWindow", 2},
			{"USER32", "GetWindowText", 2},
			{"USER32", "EnumWindows", 2},
			{"PSAPI", "GetModuleFileNameEx", 2},
		};

		for (const auto &entry : importFunctions)
		{
			for (const auto &badIAT : badImports)
			{
				if (strstr(entry.moduleName, badIAT.moduleName) != NULL && strstr(entry.functionName, badIAT.functionName) != NULL)
				{
					matchingEntries.push_back(entry);
					badScore += badIAT.score;
					// printf("FOUND: %s:%s\n", entry.moduleName, entry.functionName);
				}
			}
		}
	}

	return badScore;
}

void pe::GetPEImportFunctions(LPCWSTR filePath, std::vector<IATEntry> *importFunctions)
{

	// HMODULE hModule = LoadLibraryExW(filePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
	// if(hModule == NULL){
	// 	printf("Unable to get module handle\n");
	//     return;
	// }

	HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		std::cout << "Failed to open file. Error: " << GetLastError() << std::endl;
		return;
	}

	HANDLE hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping == NULL)
	{
		std::cout << "Failed to create file mapping. Error: " << GetLastError() << std::endl;
		CloseHandle(hFile);
		return;
	}

	void *pFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (pFileBase == NULL)
	{
		std::cout << "Failed to map view of file. Error: " << GetLastError() << std::endl;
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return;
	}

	// Get the DOS header
	IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER *)pFileBase;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		std::cout << "Invalid DOS header." << std::endl;
		UnmapViewOfFile(pFileBase);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return;
	}

	// Get the NT headers
	IMAGE_NT_HEADERS *pNtHeaders = (IMAGE_NT_HEADERS *)((BYTE *)pFileBase + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		std::cout << "Invalid NT headers." << std::endl;
		UnmapViewOfFile(pFileBase);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return;
	}

	void *pImportTable = nullptr;

	// Check if the PE is 32-bit or 64-bit
	if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		// 32-bit PE
		PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)&pNtHeaders->OptionalHeader;
		PIMAGE_DATA_DIRECTORY pImportDir = &pOptionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (pImportDir->VirtualAddress != 0)
		{
			pImportTable = (void *)((BYTE *)pFileBase + pImportDir->VirtualAddress);

			// Print the module and function names
			PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)pImportTable;
			while (pImportDescriptor->Name != 0)
			{
				char moduleName[MAX_PATH];
				DWORD moduleNameSize = sizeof(moduleName);

				HMODULE hModule = LoadLibraryA((const char *)((BYTE *)pFileBase + pImportDescriptor->Name));
				if (hModule != NULL)
				{
					GetModuleFileNameA(hModule, moduleName, moduleNameSize);
					FreeLibrary(hModule);
					std::cout << "Module: " << moduleName << std::endl;
				}
				else
				{
					std::cout << "Failed to load module." << std::endl;
				}

				PIMAGE_THUNK_DATA32 pThunkData = (PIMAGE_THUNK_DATA32)((BYTE *)pFileBase + pImportDescriptor->OriginalFirstThunk);
				while (pThunkData->u1.AddressOfData != 0)
				{
					if (pThunkData->u1.AddressOfData > 0x80000000)
					{
						// Ordinal import
						std::cout << "  Function: Ordinal " << (pThunkData->u1.AddressOfData & 0xFFFF) << std::endl;
					}
					else
					{
						// Named import
						PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE *)pFileBase + pThunkData->u1.AddressOfData);
						std::cout << "  Function: " << pImportByName->Name << std::endl;
					}
					pThunkData++;
				}

				pImportDescriptor++;
			}
		}
	}
	else if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		// 64-bit PE
		PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)&pNtHeaders->OptionalHeader;
		PIMAGE_DATA_DIRECTORY pImportDir = &pOptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (pImportDir->VirtualAddress != 0)
		{
			pImportTable = (void *)((BYTE *)pFileBase + pImportDir->VirtualAddress);

			// Print the module and function names
			PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)pImportTable;
			while (pImportDescriptor->Name != 0)
			{
				const char *moduleName = (const char *)((BYTE *)pFileBase + pImportDescriptor->Name);
				std::cout << "Module: " << moduleName << std::endl;

				PIMAGE_THUNK_DATA64 pThunkData = (PIMAGE_THUNK_DATA64)((BYTE *)pFileBase + pImportDescriptor->OriginalFirstThunk);
				while (pThunkData->u1.AddressOfData != 0)
				{
					if (pThunkData->u1.AddressOfData > 0x8000000000000000)
					{
						// Ordinal import
						std::cout << "  Function: Ordinal " << (pThunkData->u1.AddressOfData & 0xFFFF) << std::endl;
					}
					else
					{
						// Named import
						PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE *)pFileBase + pThunkData->u1.AddressOfData);
						std::cout << "  Function: " << pImportByName->Name << std::endl;
					}
					pThunkData++;
				}

				pImportDescriptor++;
			}
		}
	}

	UnmapViewOfFile(pFileBase);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);

	return;
}

VOID pe::CalculateFileHash(HANDLE hFile, BYTE *hashResult, DWORD hashLen)
{
	DWORD fileSize = GetFileSize(hFile, NULL);
	if (fileSize == INVALID_FILE_SIZE)
	{
		CloseHandle(hFile);
		return;
	}

	HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping == NULL)
	{
		CloseHandle(hFile);
		return;
	}

	LPVOID lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (lpFileBase == NULL)
	{
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return;
	}

	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		UnmapViewOfFile(lpFileBase);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return;
	}

	if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
	{
		CryptReleaseContext(hProv, 0);
		UnmapViewOfFile(lpFileBase);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return;
	}

	if (!CryptHashData(hHash, static_cast<BYTE *>(lpFileBase), fileSize, 0))
	{
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		UnmapViewOfFile(lpFileBase);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return;
	}

	if (!CryptGetHashParam(hHash, HP_HASHVAL, hashResult, &hashLen, 0))
	{
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		UnmapViewOfFile(lpFileBase);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return;
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	UnmapViewOfFile(lpFileBase);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);

	return;
}