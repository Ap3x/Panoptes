#pragma once
#include <memory>
#include <string>
#include <vector>

class PanoptesService_Stub_Holder; // the gRPC stub, kept out of this header

/// @brief What the service answered a scan request with
struct ScanReply {
	std::string Results;              // the file's stored result (JSON), empty if it has none yet
	std::string FileHash;             // the hash it's stored under
	std::vector<std::string> Pending; // results still expected: "yara_scan", "ml_scan"
};

class PanoptesServiceClient {
public:
	PanoptesServiceClient();
	~PanoptesServiceClient();
	PanoptesServiceClient(const PanoptesServiceClient&) = delete;
	PanoptesServiceClient& operator=(const PanoptesServiceClient&) = delete;
	/// @brief Asks the service to scan a file with every extension that hasn't yet. With Poll,
	/// only reads back the stored result and the scans still running (FileHash from an earlier
	/// reply, so the file needn't still be there)
	/// @return False on an error, described in Error
	bool QueuePeScan(const std::string& PePath, const std::string& FileHash, bool Poll, ScanReply& Reply, std::string& Error);

private:
	// A member, not a global: a global stub is destroyed during static teardown, after gRPC's
	// own globals, and crashes the process as it exits
	std::unique_ptr<PanoptesService_Stub_Holder> m_stub;
};
