#include "utils.hpp"

LPCWSTR utils::GetBaseName(LPCWSTR FullPath) {
	LPWSTR baseName = PathFindFileNameW(FullPath);
	return baseName;
}

std::string utils::LPTSTRToString(LPWSTR wideStr) {
	int strSize = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, nullptr, 0, nullptr, nullptr);
	std::string str(strSize, 0);
	WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, &str[0], strSize, nullptr, nullptr);
	return str;
}

LPWSTR utils::GetCurrentDir() {
    static wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    wchar_t* pos = wcsrchr(buffer, L'\\');
    if (pos != NULL) {
        *(pos + 1) = L'\0';
    }
    return buffer;
}

LPCWSTR utils::GetBinaryPathFromPID(DWORD processID)
{
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
	if (processHandle != nullptr)
	{
		LPWSTR imagePath;
		DWORD bufferSize = MAX_PATH;

		if (QueryFullProcessImageNameW(processHandle, 0, imagePath, &bufferSize))
		{
			return imagePath;
		}
		else
		{
			return L"";
		}
	}
	else
	{
		return L"";
	}
}

// VOID utils::DwordToLpctstr(DWORD value, LPTSTR buffer, int bufferSize)
// {
// 	// Convert DWORD to string
// 	int index = bufferSize - 1;
// 	buffer[index] = '\0';
// 	do {
// 		buffer[--index] = '0' + (value % 10);
// 		value /= 10;
// 	} while (value != 0);

// 	// Shift the string to the beginning of the buffer
// 	int length = bufferSize - index - 1;
// 	memmove(buffer, buffer + index, length * sizeof(TCHAR));
// }

LPWSTR utils::ConcatStrings(int count, ...)
{
    va_list args;
    va_start(args, count);
    
    // Calculate the total size required for the concatenated string
    size_t totalSize = 1; // Initialize with 1 for the null-terminator
    for (int i = 0; i < count; i++) {
        LPWSTR str = va_arg(args, LPWSTR);
        totalSize += wcslen(str);
    }
    
    // Allocate memory for the concatenated string
    LPWSTR result = new WCHAR[totalSize];
    
    // Initialize the result string as an empty string
    StringCchCopyW(result, totalSize, L"");
    
    // Reset the argument list pointer
    va_end(args);
    va_start(args, count);
    
    // Concatenate each string to the result string
    for (int i = 0; i < count; i++) {
        LPWSTR str = va_arg(args, LPWSTR);
        StringCchCatW(result, totalSize, str);
    }
    
    va_end(args);
    
    return result;
}
