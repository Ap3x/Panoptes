#pragma once
#include "ExtensibilityCore.h"
#include <vector>
extern "C" {
#include "yara_x.h"
}

#define VERSION "1.0.0"
using namespace std;

/// @brief The result of verifying a file's Authenticode signature with WinVerifyTrust
struct SignatureInfo {
	/// @brief True if the file has an embedded or catalog signature
	bool isSigned = false;
	/// @brief True if WinVerifyTrust reported the signature as valid and trusted
	bool trusted = false;
	/// @brief True if the signature came from a catalog file rather than being embedded
	bool catalogSigned = false;
	/// @brief The signing certificate's display name (UTF-8), empty if unsigned
	std::string signer;
	/// @brief The WinVerifyTrust result, 0 if trusted
	LONG trustStatus = TRUST_E_NOSIGNATURE;
};

SignatureInfo VerifyFileSignature(const std::string& PathToFile);

/// @brief The Panoptes Service Client that used to communicate via gRPC
class PanoptesServiceClient {
public:
	PanoptesServiceClient();
	bool Hello(ExtensibilityType extensibilityType, int ContainerPort);
	bool SendResults_Yara(std::string PePath, std::string FileHash, std::vector<std::string> DetectedRules, const SignatureInfo& Signature);
};

/// @brief The YaraScanner class that is used to scan a file using YARA rules
class YaraScanner {
private:
	/// @brief The parsed YARA rules
	YRX_RULES* g_yaraRules = nullptr;
public:
	/// @brief The data that is sent to the Panoptes Service
	struct ScanData
	{
		int detections;
		std::vector<std::string> detectedRules;
	};

	YaraScanner(const char* Rules);
	~YaraScanner();
	std::vector<std::string> YaraScanFile(std::string PathToFile);
};
