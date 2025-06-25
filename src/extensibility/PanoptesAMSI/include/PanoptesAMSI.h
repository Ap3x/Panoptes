#pragma once
#include "ExtensibilityCore.h"

#define VERSION "1.0.0"
using namespace std;

/// @brief Panoptes Service Client that is used to communicate with the Panoptes Service via 
class PanoptesServiceClient {
public:
	PanoptesServiceClient();
	bool Hello(ExtensibilityType extensibilityType, int ContainerPort);
	bool SendResults_AMSI(std::string PePath, std::string FileHash, DWORD AmsiResult);
};

class AmsiScanner {
public:
	/// @brief The result of the AMSI scan
	typedef enum AMSI_RESULT_PANO
	{
		AMSI_RESULT_PANO_CLEAN = 0,
		AMSI_RESULT_PANO_NOT_DETECTED = 1,
		AMSI_RESULT_PANO_BLOCKED_BY_ADMIN_START = 0x4000,
		AMSI_RESULT_PANO_BLOCKED_BY_ADMIN_END = 0x4fff,
		AMSI_RESULT_PANO_DETECTED = 32768
	} 	AMSI_RESULT_PANO;

	static HRESULT AmsiScanFile(std::string PathToFile, std::string CopyPath, int* AmsiResult);
};
