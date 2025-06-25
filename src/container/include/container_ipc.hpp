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

class MemoryMessageQueue {
public:
	std::condition_variable cv;

	void enqueue(const MemScan& message);
	MemScan dequeue();
private:
	std::queue<MemScan> queue_;
	std::mutex mutex_;
	std::condition_variable cv_;
};

class PanoptesServiceClient {
public:
	PanoptesServiceClient();
	bool Hello(ExtensibilityType extensibilityType, std::string port);
	bool SendResults_Yara(std::string PePath, std::string FileHash, DWORD ProcessId, std::string YaraRulesPath, INT MatchRules, std::vector<std::string> DetectedRules);
	bool SendResults_PE(std::string PePath, bool IsPeSigned, std::string PeSignerSubject, std::vector<std::string> PeImports);
	bool SendResults_AMSI(std::string PePath, DWORD AmsiResult);
};

VOID RunContainerServer(LPVOID ContainerPort);

extern MemoryMessageQueue* message_queue_mem_;
extern PeMessageQueue* message_queue_pe_;