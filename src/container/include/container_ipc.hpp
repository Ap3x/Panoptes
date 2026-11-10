#pragma once
#include <Windows.h>
#include <string>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include "ExtensibilityCore.h"

class PeMessageQueue {
public:
	void enqueue(const PeScan& message);
	PeScan dequeue();
	PeMessageQueue();
	~PeMessageQueue() {
		DeleteCriticalSection(&cs_);
	}
private:
	std::queue<PeScan> queue_;
	CRITICAL_SECTION cs_;
	CONDITION_VARIABLE cv_;
};

class PanoptesServiceClient {
public:
	PanoptesServiceClient();
	bool Hello(ExtensibilityType extensibilityType, std::string port);
	bool SendResults_Yara(std::string PePath, std::string FileHash, DWORD ProcessId, std::string YaraRulesPath, INT MatchRules, std::vector<std::string> DetectedRules);
};

VOID RunContainerServer(LPVOID ContainerPort);

extern PeMessageQueue* message_queue_pe_;