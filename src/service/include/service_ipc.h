#pragma once
#include <Windows.h>
#include <string>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>

class PanoptesContainerClient {
public:
	PanoptesContainerClient(int ContainerPort);
	bool SendPeScanRequest(std::string PePath, std::string FileHash);
	bool SendMemoryScanRequest(DWORD ProcessId);
};

VOID RunServiceServer(LPVOID lpParam);
