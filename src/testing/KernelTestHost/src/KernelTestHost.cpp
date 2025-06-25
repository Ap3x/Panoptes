// Testhost_Kernel.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "panoptes_trace.h"
#include <string>

int main()
{
	TraceInit();
	HANDLE ProcessId = (HANDLE)GetCurrentProcessId();
	HANDLE ThreadId = (HANDLE)GetCurrentThreadId();
	std::wstring myWString = L"..\\..\\assets\\yara\\eicarcom2.zip";
	PWCH myPWCH = const_cast<PWCH>(myWString.c_str());
	while (1) {
		printf("Press Enter to log a file creation event\n");
		int test = getchar();
		Log_FileCreated(ProcessId, ThreadId, myPWCH, false);
	}
}
