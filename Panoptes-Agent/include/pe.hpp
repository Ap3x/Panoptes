#pragma once
#include "framework.h"

#include <string>
#include <vector>
#include <unordered_map>

#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <ImageHlp.h>

struct IATEntry
{
    LPCSTR moduleName;
    LPCSTR functionName;
    // PVOID addressOfData;
};

struct BadImports
{
    LPCSTR moduleName;
    LPCSTR functionName;
    int score;
};

class pe {
public:
	static BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile);
	static INT CheckForImportFunctions(LPCWSTR PortableExecutablePath);
	static VOID CalculateFileHash(HANDLE hFile, BYTE* hashResult, DWORD hashLen);
private:
	static void GetPEImportFunctions(LPCWSTR filePath, std::vector<IATEntry>* importFunctions);
	static std::vector<IATEntry> GetImportAddressTable(LPCWSTR filePath);
	// static void GetImportAddressTableNEW(HMODULE hModule);

};

