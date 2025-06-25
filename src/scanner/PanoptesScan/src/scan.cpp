#include <iostream>
#include <vector>
#include "scanner_ipc.hpp"
#include <Windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	std::string fileToScan = __argv[1];
	PanoptesServiceClient client = PanoptesServiceClient();
	std::string results;
	if (!client.QueuePeScan(fileToScan, "", results)) {
		MessageBoxA(NULL, results.c_str(), "Panoptes Scan", MB_OK | MB_ICONERROR);
	}

	return 0;
}

