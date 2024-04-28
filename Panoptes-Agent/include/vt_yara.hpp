#pragma once
#include "framework.h"
#include "yara.h"
#include "utils.hpp"
#include <wchar.h>

#define RULES_FOLDER L"C:\\Users\\Research\\source\\repos\\Test-Yara\\rules-master\\rules-master"

class vt_yara
{
public:
	YR_COMPILER* compiler = NULL;
	YR_RULES* rules = NULL;
	struct COUNTERS
	{
		int rules_matching;
		int rules_not_matching;
		int rules_warning;
	};

	static BOOL StaticScan(LPCWSTR PEPath, YR_COMPILER* compiler, YR_RULES* rules);
	static BOOL ScanMem(PVOID BaseAddress, SIZE_T NumberOfBytesToWrite,  YR_RULES* rules);
	static VOID CompileYaraRules(LPCWSTR folderPath, YR_COMPILER* compiler);
	static VOID CleanUp();
private:
	static INT count(YR_SCAN_CONTEXT * context, int message, void* message_data, void* user_data);

};

