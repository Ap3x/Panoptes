#pragma once
#include <Windows.h>
#include <string>

class PanoptesContainerClient {
public:
	PanoptesContainerClient(int ContainerPort);
	bool SendPeScanRequest(std::string PePath, std::string FileHash);
	bool SendMemoryScanRequest(DWORD ProcessId);
};

void SelfQueuePeScan(std::string pePath, std::string fileHash);
VOID RunServiceServer(LPVOID lpParam);