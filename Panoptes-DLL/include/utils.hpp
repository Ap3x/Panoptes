#pragma once
#include "framework.h"

class utils
{
public:
	static LPWSTR GetCurrentDir();
	static LPCWSTR GetBinaryPathFromPID(DWORD processID);
	static LPCWSTR GetBaseName(LPCWSTR FullPath);
	static std::string LPTSTRToString(LPWSTR wideStr);
	// static VOID DwordToLpctstr(DWORD value, LPTSTR buffer, int bufferSize);
	static LPWSTR ConcatStrings(int count, ...);
};

