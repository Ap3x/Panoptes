#pragma once
#include <string>

class PanoptesServiceClient {
public:
	PanoptesServiceClient();
	bool QueuePeScan(std::string PePath, std::string FileHash, std::string& message);
};
