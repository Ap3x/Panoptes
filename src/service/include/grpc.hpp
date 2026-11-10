#pragma once
#include <Windows.h>
#include <string>

class PanoptesContainerClient {
public:
	PanoptesContainerClient(int ContainerPort);
	bool SendPeScanRequest(std::string PePath, std::string FileHash);
};

void SelfQueuePeScan(std::string pePath, std::string fileHash);
VOID RunServiceServer(LPVOID lpParam);

/// @brief Shuts down the server RunServiceServer started, cancelling calls still in flight
/// after a short grace period, so RunServiceServer returns. Safe to call if it never started
VOID StopServiceServer();
