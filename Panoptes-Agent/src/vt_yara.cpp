#include "vt_yara.hpp"

int vt_yara::count(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
{
	//YR_DEBUG_FPRINTF(
	//	2,
	//	stderr,
	//	"- %s(message=%d AKA %s) {}\n",
	//	__FUNCTION__,
	//	message,
	//	yr_debug_callback_message_as_string(message));

	switch (message)
	{
	case CALLBACK_MSG_TOO_MANY_MATCHES:
		(*(struct COUNTERS*)user_data).rules_warning++;
		break;

	case CALLBACK_MSG_RULE_MATCHING:
		(*(struct COUNTERS*)user_data).rules_matching++;
		break;

	case CALLBACK_MSG_RULE_NOT_MATCHING:
		(*(struct COUNTERS*)user_data).rules_not_matching++;
	}
	return CALLBACK_CONTINUE;

}

VOID vt_yara::CompileYaraRules(LPCWSTR folderPath, YR_COMPILER* compiler) {
	WIN32_FIND_DATAW findData;
	HANDLE hFind;

	// Build the search pattern
	// LPWSTR searchPattern;
	// wcscat_s(searchPattern, sizeof(MAX_PATH),folderPath);
	// wcscat_s(searchPattern, sizeof(MAX_PATH),L"\\*");
	LPWSTR searchPattern = utils::ConcatStrings(2, folderPath, L"\\*");

	// Find the first file or folder in the current folder
	hFind = FindFirstFileW((LPCWSTR)searchPattern, &findData);
	if (hFind == INVALID_HANDLE_VALUE) {
		wprintf(L"Failed to find files or folders in the current folder.\n");
		return;
	}

	do {
		// Check if the found item is a directory
		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			// Skip "." and ".." directories
			if (lstrcmpW((LPCWSTR)findData.cFileName, L".") != 0 && lstrcmpW((LPCWSTR)findData.cFileName, L"..") != 0) {
				// LPWSTR subFolderPath;
				// wcscat_s(subFolderPath, sizeof(MAX_PATH),folderPath);
				// wcscat_s(subFolderPath,sizeof(MAX_PATH), L"\\");
				// wcscat_s(subFolderPath, sizeof(MAX_PATH),(LPCWSTR)findData.cFileName);
				LPWSTR subFolderPath = utils::ConcatStrings(3,  folderPath, L"\\", findData.cFileName);

				// Recursively process the subfolder
				CompileYaraRules(subFolderPath, compiler);
			}
		}
		else {
			// Check if the file has a ".yar" extension
			LPCWSTR extension = PathFindExtensionW((LPCWSTR)findData.cFileName);
			if (wcscmp(extension, L".yar") == 0) {
				// LPWSTR filePath;
				// wcscat_s(filePath, sizeof(MAX_PATH),folderPath);
				// wcscat_s(filePath, sizeof(MAX_PATH),L"\\");
				// wcscat_s(filePath, sizeof(MAX_PATH),(LPCWSTR)findData.cFileName);
				LPWSTR filePath = utils::ConcatStrings(3,  folderPath, L"\\", findData.cFileName);

				// Open a handle to the file
				HANDLE hFile = CreateFileW(
					filePath,
					GENERIC_READ,
					FILE_SHARE_READ,
					NULL,
					OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL,
					NULL
				);

				if (hFile != INVALID_HANDLE_VALUE) {
					//wprintf(TEXT("Opened file: %s\n"), filePath);
					// Perform operations with the file handle
					// ...
					CloseHandle(hFile);
				}
				else {
					wprintf(L"Failed to open file: %ls\n", filePath);
				}
			}
		}
	} while (FindNextFileW(hFind, &findData) != 0);

	FindClose(hFind);
}

BOOL vt_yara::StaticScan(LPCWSTR PEPath, YR_COMPILER* compiler, YR_RULES* rules) {
	//wprintf(TEXT("[+] Yara Scaning: %s\n"), PEPath);
	COUNTERS counters = { 0 };
	counters.rules_not_matching = 0;
	counters.rules_matching = 0;
	counters.rules_warning = 0;

	int length = WideCharToMultiByte(CP_ACP, 0, PEPath, -1, NULL, 0, NULL, NULL);
	char* cstr = new char[length];
	WideCharToMultiByte(CP_ACP, 0, PEPath, -1, cstr, length, NULL, NULL);
	if (yr_rules_scan_file(rules, cstr, 0, count, &counters, 5000) != ERROR_SUCCESS)
	{
		perror("yr_rules_scan_file");
		return false;
	}

	if (counters.rules_matching > 0) {
		return true;
	}

	return false;
}

BOOL vt_yara::ScanMem(PVOID BaseAddress, SIZE_T NumberOfBytesToWrite, YR_RULES* rules) {
	//wprintf(TEXT("[+] Yara Scaning: %s\n"), PEPath);
	COUNTERS counters = { 0 };
	counters.rules_not_matching = 0;
	counters.rules_matching = 0;
	counters.rules_warning = 0;

	// yr_initialize();
	// yr_compiler_create(&compiler);
	// CompileYaraRules(RULES_FOLDER, compiler);

	// if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS)
	// {
	// 	yr_compiler_destroy(compiler);
	// 	perror("yr_compiler_get_rules");
	// 	yr_finalize();
	// 	return false;
	// }

	//int length = WideCharToMultiByte(CP_ACP, 0, PEPath, -1, NULL, 0, NULL, NULL);
	//char* cstr = new char[length];
	//WideCharToMultiByte(CP_ACP, 0, PEPath, -1, cstr, length, NULL, NULL);

	if (yr_rules_scan_mem(rules, (const uint8_t*)BaseAddress, NumberOfBytesToWrite, 0, count, &counters, 5000)) {
		perror("yr_rules_scan_file");
		//exit(EXIT_FAILURE);
		return false;
	}
	//if (yr_rules_scan_file(rules, cstr, 0, count, &counters, 5000) != ERROR_SUCCESS)
	//{
	//	perror("yr_rules_scan_file");
	//	//exit(EXIT_FAILURE);
	//	return false;
	//}

	if (counters.rules_matching > 0) {
		//yr_finalize();
		return true;
	}


	//yr_scan_context_destroy(&context);
	//yr_rules_destroy(rules);
	//yr_finalize();
	return false;
}

VOID vt_yara::CleanUp() {
	yr_finalize();
	return;
}